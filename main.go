package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-secretsmanager/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

var defaultPolicyBehaviors = map[string][]string{
	"plugin-aws-secretsmanager-rotation-policies":        {resourceTypeSecret},
	"plugin-aws-secretsmanager-vendor-policies":          {resourceTypeSecret},
	"plugin-aws-secretsmanager-confidentiality-policies": {resourceTypeSecret},
	"plugin-aws-secretsmanager-privacy-policies":         {resourceTypeSecret},
	"plugin-aws-secretsmanager-secret-policies":          {resourceTypeSecret},
}

func requestWithDefaultPolicyBehavior(req *proto.EvalRequest) *proto.EvalRequest {
	if req == nil {
		return nil
	}
	return req.
		WithDefaultPolicyBehavior(defaultPolicyBehaviors).
		WithUndefinedMappedTo([]string{resourceTypeSecret})
}

type CompliancePlugin struct {
	mu           sync.RWMutex
	logger       hclog.Logger
	rawConfig    map[string]string
	parsedConfig *PluginConfig
	factory      AWSClientFactory
	policyData   map[string]interface{}
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	parsed, err := parsePluginConfig(req.GetConfig())
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rawConfig = cloneStringMap(req.GetConfig())
	l.parsedConfig = parsed
	if req.GetPolicyData() != nil {
		l.policyData = req.GetPolicyData().AsMap()
	} else {
		l.policyData = parsed.PolicyInputs
	}
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, buildSubjectTemplates())
}

func (l *CompliancePlugin) Eval(req *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	if req == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("eval request is nil")
	}
	ctx := context.Background()

	l.mu.RLock()
	parsedConfig := l.parsedConfig
	policyData := l.policyData
	l.mu.RUnlock()
	if parsedConfig == nil || policyData == nil {
		l.mu.Lock()
		if l.parsedConfig == nil {
			defaults, err := parsePluginConfig(map[string]string{})
			if err != nil {
				l.mu.Unlock()
				return nil, err
			}
			l.parsedConfig = defaults
		}
		if l.policyData == nil {
			l.policyData = map[string]interface{}{}
		}
		parsedConfig = l.parsedConfig
		policyData = clonePolicyInputs(l.policyData)
		l.mu.Unlock()
	} else {
		policyData = clonePolicyInputs(policyData)
	}
	policyLabels := cloneStringMap(parsedConfig.PolicyLabels)

	policyRequest := requestWithDefaultPolicyBehavior(req)
	pathsByType := map[string][]string{
		resourceTypeSecret: policyRequest.PolicyPathsForBehavior(resourceTypeSecret),
	}

	logger := l.logger
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	collector := &Collector{Logger: logger.Named("collector"), Config: parsedConfig, Factory: l.factory}
	result := collector.Collect(ctx)

	evidences := make([]*proto.Evidence, 0)
	var accumulated error
	accumulated = errors.Join(accumulated, result.Err)
	for _, record := range result.Records {
		recordEvidence, err := l.evaluateRecord(ctx, pathsByType[record.Input.Resource.Type], record, policyLabels, policyData)
		evidences = append(evidences, recordEvidence...)
		accumulated = errors.Join(accumulated, err)
	}

	if len(evidences) > 0 && apiHelper != nil {
		if createErr := apiHelper.CreateEvidence(ctx, evidences); createErr != nil {
			accumulated = errors.Join(accumulated, createErr)
		}
	}
	if accumulated != nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, accumulated
	}
	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func (l *CompliancePlugin) evaluateRecord(
	ctx context.Context,
	policyPaths []string,
	record *ResourceRecord,
	policyLabels map[string]string,
	policyData map[string]interface{},
) ([]*proto.Evidence, error) {
	var accumulated error
	evidences := make([]*proto.Evidence, 0)
	labels := internal.MergeMaps(policyLabels, record.Labels)
	activities := []*proto.Activity{{
		Title:       "Collect AWS Secrets Manager evidence",
		Description: "Collected read-only Secrets Manager configuration, resource policies, version stages, and CloudTrail data for policy evaluation.",
		Steps: []*proto.Step{
			{Title: "Fetch read-only AWS data", Description: "Used AWS SDK read-only Secrets Manager, CloudTrail, and STS APIs."},
			{Title: "Normalize Rego input", Description: "Converted SDK payloads into the documented aws-secretsmanager Rego input schema."},
		},
	}}
	input, err := regoInputMap(record.Input)
	if err != nil {
		return nil, err
	}
	for _, policyPath := range policyPaths {
		processor := policyManager.NewPolicyProcessor(
			l.logger, labels, subjectsForRecord(*record), defaultComponents(),
			inventoryForRecord(*record), defaultActors(), activities, policyData,
		)
		evidence, perr := processor.GenerateResults(ctx, policyPath, input)
		evidences = append(evidences, evidence...)
		if perr != nil {
			accumulated = errors.Join(accumulated, perr)
		}
	}
	return evidences, accumulated
}

func regoInputMap(input NormalizedInput) (map[string]interface{}, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal Rego input: %w", err)
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, fmt.Errorf("unmarshal Rego input: %w", err)
	}
	return out, nil
}

func buildSubjectTemplates() []*proto.SubjectTemplate {
	return []*proto.SubjectTemplate{
		{
			Name:                "aws-secretsmanager-secret",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "Secrets Manager secret {{ .resource_id }} in {{ .account_id }}/{{ .region }}",
			DescriptionTemplate: "AWS Secrets Manager secret {{ .resource_id }}.",
			PurposeTemplate:     "Represents a Secrets Manager secret evaluated for compliance posture.",
			IdentityLabelKeys:   []string{"account_id", "region", "resource_id"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID"},
				{Key: "region", Description: "AWS region"},
				{Key: "resource_id", Description: "Secret friendly name + 6-char suffix"},
				{Key: "resource_arn", Description: "Secret ARN"},
			},
		},
	}
}

func subjectsForRecord(record ResourceRecord) []*proto.Subject {
	return []*proto.Subject{{
		Identifier:  record.SubjectID,
		Type:        record.SubjectType,
		Description: "AWS Secrets Manager secret " + record.Input.Resource.ID,
	}}
}

func defaultComponents() []*proto.Component {
	return []*proto.Component{{
		Identifier:  sourceName,
		Type:        "software",
		Title:       "AWS Secrets Manager collector",
		Description: "Read-only collector for AWS Secrets Manager compliance evidence.",
	}}
}

func inventoryForRecord(record ResourceRecord) []*proto.InventoryItem {
	return []*proto.InventoryItem{{
		Identifier:  record.Input.Resource.ARN,
		Type:        "aws-secretsmanager-secret",
		Title:       record.Title,
		Description: "AWS Secrets Manager secret in " + record.Input.Region.Name,
	}}
}

func defaultActors() []*proto.OriginActor {
	return []*proto.OriginActor{{
		UUID:  sourceName,
		Title: "AWS Secrets Manager evidence collector",
		Type:  "tool",
	}}
}

func defaultLogLevel() hclog.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL"))) {
	case "debug":
		return hclog.Debug
	case "warn":
		return hclog.Warn
	case "error":
		return hclog.Error
	case "info":
		return hclog.Info
	default:
		return hclog.Info
	}
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{Level: defaultLogLevel(), JSONFormat: true})
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins:         map[string]goplugin.Plugin{"runner": &runner.RunnerV2GRPCPlugin{Impl: &CompliancePlugin{logger: logger}}},
		GRPCServer:      goplugin.DefaultGRPCServer,
	})
}
