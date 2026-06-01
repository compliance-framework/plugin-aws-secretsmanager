package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/compliance-framework/plugin-aws-secretsmanager/internal"
	"github.com/hashicorp/go-hclog"
)

var secretsManagerEventNames = map[string]bool{
	"RotateSecret":             true,
	"PutSecretValue":           true,
	"UpdateSecret":             true,
	"UpdateSecretVersionStage": true,
	"DeleteSecret":             true,
	"RestoreSecret":            true,
	"PutResourcePolicy":        true,
	"DeleteResourcePolicy":     true,
	"TagResource":              true,
	"UntagResource":            true,
	"CreateSecret":             true,
	"GetSecretValue":           true,
}

var iamCredentialRemovalEventNames = map[string]bool{
	"DeleteUser":                    true,
	"DeleteAccessKey":               true,
	"DetachUserPolicy":              true,
	"RemoveUserFromGroup":           true,
	"DeleteRole":                    true,
	"DetachRolePolicy":              true,
	"RemoveRoleFromInstanceProfile": true,
}

type SecretsManagerAPI interface {
	ListSecrets(context.Context, *sm.ListSecretsInput, ...func(*sm.Options)) (*sm.ListSecretsOutput, error)
	DescribeSecret(context.Context, *sm.DescribeSecretInput, ...func(*sm.Options)) (*sm.DescribeSecretOutput, error)
	GetResourcePolicy(context.Context, *sm.GetResourcePolicyInput, ...func(*sm.Options)) (*sm.GetResourcePolicyOutput, error)
	ListSecretVersionIds(context.Context, *sm.ListSecretVersionIdsInput, ...func(*sm.Options)) (*sm.ListSecretVersionIdsOutput, error)
}

type CloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

type STSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type AWSClientSet struct {
	SecretsManager SecretsManagerAPI
	CloudTrail     CloudTrailAPI
	IAMCloudTrail  CloudTrailAPI
	STS            STSAPI
}

type AWSClientFactory interface {
	ResolveTargets(context.Context, *PluginConfig) ([]ResolvedTarget, error)
	ClientsForTarget(context.Context, ResolvedTarget) (AWSClientSet, error)
}

type ResolvedTarget struct {
	AccountID string
	Region    string
	RoleARN   string
	Tags      map[string]string
	Config    aws.Config
}

type DefaultAWSClientFactory struct{}

func (DefaultAWSClientFactory) ResolveTargets(ctx context.Context, cfg *PluginConfig) ([]ResolvedTarget, error) {
	base, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	accounts := cfg.Accounts
	if len(accounts) == 0 {
		accounts = []AccountConfig{{Regions: cfg.DefaultRegions}}
	}
	targets := make([]ResolvedTarget, 0)
	for _, account := range accounts {
		regions := account.Regions
		if len(regions) == 0 {
			regions = cfg.DefaultRegions
		}
		if len(regions) == 0 && base.Region != "" {
			regions = []string{base.Region}
		}
		if len(regions) == 0 {
			return nil, fmt.Errorf("no AWS region resolved for account %q; set account regions, default_regions, or AWS_REGION", account.AccountID)
		}
		for _, region := range regions {
			awsCfg := base.Copy()
			awsCfg.Region = region
			if account.RoleARN != "" {
				opts := func(o *stscreds.AssumeRoleOptions) {
					if account.ExternalID != "" {
						o.ExternalID = aws.String(account.ExternalID)
					}
					if account.SessionName != "" {
						o.RoleSessionName = account.SessionName
					}
				}
				awsCfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(awsCfg), account.RoleARN, opts))
			}
			accountID := account.AccountID
			if accountID == "" {
				ident, identErr := sts.NewFromConfig(awsCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
				if identErr != nil {
					return nil, fmt.Errorf("resolve account id for region %q: %w", region, identErr)
				}
				accountID = aws.ToString(ident.Account)
			}
			targets = append(targets, ResolvedTarget{
				AccountID: accountID,
				Region:    region,
				RoleARN:   account.RoleARN,
				Tags:      cloneStringMap(account.Tags),
				Config:    awsCfg,
			})
		}
	}
	return targets, nil
}

func (DefaultAWSClientFactory) ClientsForTarget(_ context.Context, target ResolvedTarget) (AWSClientSet, error) {
	iamCloudTrailConfig := target.Config.Copy()
	iamCloudTrailConfig.Region = "us-east-1"
	return AWSClientSet{
		SecretsManager: sm.NewFromConfig(target.Config),
		CloudTrail:     cloudtrail.NewFromConfig(target.Config),
		IAMCloudTrail:  cloudtrail.NewFromConfig(iamCloudTrailConfig),
		STS:            sts.NewFromConfig(target.Config),
	}, nil
}

type Collector struct {
	Logger  hclog.Logger
	Config  *PluginConfig
	Factory AWSClientFactory
}

type CollectionResult struct {
	Records []*ResourceRecord
	Errors  map[string][]error
	Err     error
}

type secretDraft struct {
	arn       string
	name      string
	config    map[string]interface{}
	dynamic   map[string]interface{}
	tags      map[string]string
	hashes    map[string]string
	errors    []CollectionError
	describe  *sm.DescribeSecretOutput
	principal []string
}

type normalizedEvent struct {
	EventName       string   `json:"event_name"`
	EventTime       string   `json:"event_time"`
	UserIdentityARN string   `json:"user_identity_arn"`
	AWSRegion       string   `json:"aws_region"`
	EventID         string   `json:"event_id"`
	Resources       []string `json:"resources"`
}

type collectedEvent struct {
	normalized normalizedEvent
	raw        string
	params     map[string]interface{}
	source     string
}

func (c *Collector) Collect(ctx context.Context) *CollectionResult {
	cfg := c.Config
	if cfg == nil {
		cfg, _ = parsePluginConfig(map[string]string{})
	}
	factory := c.Factory
	if factory == nil {
		factory = DefaultAWSClientFactory{}
	}
	targets, err := factory.ResolveTargets(ctx, cfg)
	if err != nil {
		return &CollectionResult{Errors: map[string][]error{"target": {err}}, Err: err}
	}
	workers := cfg.MaxConcurrency
	if workers <= 0 {
		workers = 1
	}
	if workers > len(targets) && len(targets) > 0 {
		workers = len(targets)
	}
	if workers == 0 {
		workers = 1
	}

	result := &CollectionResult{Errors: map[string][]error{}}
	var mu sync.Mutex
	jobs := make(chan ResolvedTarget)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				// APITimeoutSeconds bounds the entire per-target collection across all paginated AWS calls.
				targetCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.APITimeoutSeconds)*time.Second)
				records, scopedErrors, collectErr := c.collectTarget(targetCtx, factory, target, cfg)
				cancel()
				mu.Lock()
				result.Records = append(result.Records, records...)
				for scope, errs := range scopedErrors {
					result.Errors[scope] = append(result.Errors[scope], errs...)
				}
				result.Err = errors.Join(result.Err, collectErr)
				mu.Unlock()
			}
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	wg.Wait()
	return result
}

func (c *Collector) collectTarget(ctx context.Context, factory AWSClientFactory, target ResolvedTarget, cfg *PluginConfig) ([]*ResourceRecord, map[string][]error, error) {
	scopedErrors := map[string][]error{}
	var accumulated error
	clients, err := factory.ClientsForTarget(ctx, target)
	if err != nil {
		scopedErrors["target"] = append(scopedErrors["target"], err)
		return nil, scopedErrors, err
	}
	collectedAt := time.Now().UTC()
	lookbackStart := collectedAt.AddDate(0, 0, -cfg.LookbackDays)
	lookback := &Window{Start: lookbackStart.Format(time.RFC3339), End: collectedAt.Format(time.RFC3339)}

	secretARNs, listErr := listSecretARNs(ctx, clients.SecretsManager)
	if listErr != nil {
		scopedErrors["target"] = append(scopedErrors["target"], listErr)
		return nil, scopedErrors, listErr
	}
	drafts := make(map[string]*secretDraft, len(secretARNs))
	for _, arn := range secretARNs {
		draft, perErr := c.collectSecret(ctx, clients.SecretsManager, arn)
		drafts[arn] = draft
		for _, e := range draft.errors {
			scopedErrors[arn] = append(scopedErrors[arn], errors.New(e.Message))
		}
		accumulated = errors.Join(accumulated, perErr)
	}

	smEvents, smCollected, smErr := lookupEvents(ctx, clients.CloudTrail, "secretsmanager.amazonaws.com", secretsManagerEventNames, lookbackStart, collectedAt)
	if smErr != nil {
		scopedErrors["target"] = append(scopedErrors["target"], smErr)
		accumulated = errors.Join(accumulated, smErr)
	}
	iamCloudTrail := clients.IAMCloudTrail
	if iamCloudTrail == nil {
		iamCloudTrail = clients.CloudTrail
	}
	iamEvents, iamCollected, iamErr := lookupEvents(ctx, iamCloudTrail, "iam.amazonaws.com", iamCredentialRemovalEventNames, lookbackStart, collectedAt)
	if iamErr != nil {
		scopedErrors["target"] = append(scopedErrors["target"], iamErr)
		accumulated = errors.Join(accumulated, iamErr)
	}
	cloudTrailCollected := smCollected || iamCollected
	attachSecretsManagerEvents(drafts, smEvents)
	attachIAMCredentialEvents(drafts, iamEvents)

	records := make([]*ResourceRecord, 0, len(drafts))
	for _, arn := range secretARNs {
		d := drafts[arn]
		records = append(records, newSecretRecord(target, arn, d.config, d.dynamic, d.tags, d.errors, d.hashes, lookback, cfg.PolicyInputs, cloudTrailCollected, collectedAt))
	}
	return records, scopedErrors, accumulated
}

func listSecretARNs(ctx context.Context, client SecretsManagerAPI) ([]string, error) {
	var arns []string
	var token *string
	for {
		out, err := client.ListSecrets(ctx, &sm.ListSecretsInput{IncludePlannedDeletion: aws.Bool(true), NextToken: token})
		if err != nil {
			return arns, fmt.Errorf("list secrets: %w", err)
		}
		for _, item := range out.SecretList {
			arn := aws.ToString(item.ARN)
			if arn != "" {
				arns = append(arns, arn)
			}
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}
	return arns, nil
}

func (c *Collector) collectSecret(ctx context.Context, client SecretsManagerAPI, arn string) (*secretDraft, error) {
	d := &secretDraft{
		arn:     arn,
		config:  map[string]interface{}{},
		dynamic: map[string]interface{}{"cloudtrail_events": []normalizedEvent{}, "iam_credential_removal_events": []normalizedEvent{}},
		tags:    map[string]string{},
		hashes:  map[string]string{"describe": internal.Sha256Hex(nil), "policy": internal.Sha256Hex(nil), "versions": internal.Sha256Hex(nil)},
	}
	var accumulated error
	describe, err := client.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: aws.String(arn)})
	if err != nil {
		e := fmt.Errorf("describe secret %s: %w", arn, err)
		d.errors = append(d.errors, CollectionError{Scope: arn, Message: e.Error()})
		return d, e
	}
	d.describe = describe
	d.name = aws.ToString(describe.Name)
	if payload, marshalErr := json.Marshal(describe); marshalErr == nil {
		d.hashes["describe"] = internal.Sha256Hex(payload)
	}
	for _, tag := range describe.Tags {
		k := aws.ToString(tag.Key)
		if k != "" {
			d.tags[k] = aws.ToString(tag.Value)
		}
	}
	d.config = describeConfig(arn, describe)

	policyPresent := false
	policyInfo := map[string]interface{}{"hash": "", "document": nil, "principals": []map[string]interface{}{}}
	d.config["resource_policy"] = policyInfo
	d.config["resource_policy_present"] = policyPresent
	d.config["versions"] = []map[string]interface{}{}
	d.config["deprecated_version_count"] = 0
	if describe.DeletedDate != nil {
		return d, nil
	}
	policyOut, policyErr := client.GetResourcePolicy(ctx, &sm.GetResourcePolicyInput{SecretId: aws.String(arn)})
	if policyErr != nil {
		var notFound *smtypes.ResourceNotFoundException
		if !errors.As(policyErr, &notFound) {
			e := fmt.Errorf("get resource policy %s: %w", arn, policyErr)
			d.errors = append(d.errors, CollectionError{Scope: arn, Message: e.Error()})
			accumulated = errors.Join(accumulated, e)
		}
	} else {
		if payload, marshalErr := json.Marshal(policyOut); marshalErr == nil {
			d.hashes["policy"] = internal.Sha256Hex(payload)
		}
		rawPolicy := aws.ToString(policyOut.ResourcePolicy)
		if rawPolicy != "" {
			policyPresent = true
			policyInfo = parseResourcePolicy(rawPolicy)
			d.principal = principalsFromPolicyInfo(policyInfo)
		}
	}
	d.config["resource_policy"] = policyInfo
	d.config["resource_policy_present"] = policyPresent

	versions, versionsHash, deprecatedCount, versionErr := listVersions(ctx, client, arn)
	d.hashes["versions"] = versionsHash
	d.config["versions"] = versions
	d.config["deprecated_version_count"] = deprecatedCount
	if versionErr != nil {
		e := fmt.Errorf("list secret versions %s: %w", arn, versionErr)
		d.errors = append(d.errors, CollectionError{Scope: arn, Message: e.Error()})
		accumulated = errors.Join(accumulated, e)
	}
	return d, accumulated
}

func describeConfig(arn string, describe *sm.DescribeSecretOutput) map[string]interface{} {
	kmsKeyID := aws.ToString(describe.KmsKeyId)
	if kmsKeyID == "" {
		kmsKeyID = "aws/secretsmanager"
	}
	rotationRules := map[string]interface{}{
		"automatically_after_days": int64(0),
		"schedule_expression":      "",
		"duration":                 "",
	}
	if describe.RotationRules != nil {
		rotationRules["automatically_after_days"] = internal.Int64Value(describe.RotationRules.AutomaticallyAfterDays)
		rotationRules["schedule_expression"] = aws.ToString(describe.RotationRules.ScheduleExpression)
		rotationRules["duration"] = aws.ToString(describe.RotationRules.Duration)
	}
	replicationStatus := make([]map[string]interface{}, 0, len(describe.ReplicationStatus))
	for _, r := range describe.ReplicationStatus {
		replicationStatus = append(replicationStatus, map[string]interface{}{
			"region":             aws.ToString(r.Region),
			"status":             string(r.Status),
			"last_accessed_date": internal.FormatTime(r.LastAccessedDate),
			"status_message":     aws.ToString(r.StatusMessage),
		})
	}
	return map[string]interface{}{
		"secret_arn":           arn,
		"name_hash":            internal.HashString(aws.ToString(describe.Name)),
		"kms_key_id":           kmsKeyID,
		"rotation_enabled":     describe.RotationEnabled != nil && *describe.RotationEnabled,
		"rotation_lambda_arn":  aws.ToString(describe.RotationLambdaARN),
		"rotation_rules":       rotationRules,
		"last_rotated_date":    internal.FormatTime(describe.LastRotatedDate),
		"last_changed_date":    internal.FormatTime(describe.LastChangedDate),
		"last_accessed_date":   internal.FormatTime(describe.LastAccessedDate),
		"deleted_date":         internal.FormatTime(describe.DeletedDate),
		"recovery_window_days": 0,
		"owning_service":       aws.ToString(describe.OwningService),
		"replication_status":   replicationStatus,
		"description_hash":     internal.HashString(aws.ToString(describe.Description)),
	}
}

func parseResourcePolicy(raw string) map[string]interface{} {
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		doc = map[string]interface{}{"_parse_error": err.Error()}
	}
	principals := []map[string]interface{}{}
	for _, stmt := range policyStatements(doc["Statement"]) {
		effect, _ := stmt["Effect"].(string)
		actions := stringList(stmt["Action"])
		condition := stmt["Condition"]
		for _, principal := range principalStrings(stmt["Principal"]) {
			principals = append(principals, map[string]interface{}{
				"principal": principal,
				"action":    actions,
				"condition": condition,
				"effect":    effect,
			})
		}
	}
	return map[string]interface{}{
		"hash":       internal.HashString(raw),
		"document":   doc,
		"principals": principals,
	}
}

func policyStatements(v interface{}) []map[string]interface{} {
	switch t := v.(type) {
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(t))
		for _, item := range t {
			if m, ok := item.(map[string]interface{}); ok {
				out = append(out, m)
			}
		}
		return out
	case map[string]interface{}:
		return []map[string]interface{}{t}
	default:
		return nil
	}
}

func stringList(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return []string{}
	}
}

func principalStrings(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		out := []string{}
		for _, item := range t {
			out = append(out, principalStrings(item)...)
		}
		return out
	case map[string]interface{}:
		out := []string{}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, principalStrings(t[k])...)
		}
		return out
	default:
		return []string{}
	}
}

func principalsFromPolicyInfo(policy map[string]interface{}) []string {
	raw, _ := policy["principals"].([]map[string]interface{})
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if p, ok := item["principal"].(string); ok {
			out = append(out, p)
		}
	}
	return out
}

func listVersions(ctx context.Context, client SecretsManagerAPI, arn string) ([]map[string]interface{}, string, int, error) {
	var pages []*sm.ListSecretVersionIdsOutput
	versions := []map[string]interface{}{}
	deprecated := 0
	var token *string
	var accumulated error
	includeDeprecated := true
	for {
		out, err := client.ListSecretVersionIds(ctx, &sm.ListSecretVersionIdsInput{SecretId: aws.String(arn), IncludeDeprecated: aws.Bool(includeDeprecated), NextToken: token})
		if err != nil {
			accumulated = errors.Join(accumulated, err)
			break
		}
		pages = append(pages, out)
		for _, entry := range out.Versions {
			stages := append([]string{}, entry.VersionStages...)
			if len(stages) == 0 {
				deprecated++
			}
			versions = append(versions, map[string]interface{}{
				"version_id":   aws.ToString(entry.VersionId),
				"created_date": internal.FormatTime(entry.CreatedDate),
				"kms_key_ids":  append([]string{}, entry.KmsKeyIds...),
				"stages":       stages,
			})
		}
		if out.NextToken == nil || aws.ToString(out.NextToken) == "" {
			break
		}
		token = out.NextToken
	}
	payload, _ := json.Marshal(pages)
	return versions, internal.Sha256Hex(payload), deprecated, accumulated
}

func lookupEvents(ctx context.Context, client CloudTrailAPI, source string, allowed map[string]bool, start, end time.Time) ([]collectedEvent, bool, error) {
	out := []collectedEvent{}
	var token *string
	for {
		page, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(start),
			EndTime:   aws.Time(end),
			LookupAttributes: []cttypes.LookupAttribute{{
				AttributeKey:   cttypes.LookupAttributeKeyEventSource,
				AttributeValue: aws.String(source),
			}},
			NextToken: token,
		})
		if err != nil {
			return out, len(out) > 0, fmt.Errorf("lookup CloudTrail %s: %w", source, err)
		}
		for _, event := range page.Events {
			name := aws.ToString(event.EventName)
			if !allowed[name] {
				continue
			}
			raw := aws.ToString(event.CloudTrailEvent)
			params, userARN, region := parseCloudTrailRaw(raw)
			out = append(out, collectedEvent{
				normalized: normalizedEvent{
					EventName:       name,
					EventTime:       internal.FormatTime(event.EventTime),
					UserIdentityARN: userARN,
					AWSRegion:       region,
					EventID:         aws.ToString(event.EventId),
					Resources:       eventResourceNames(event.Resources),
				},
				raw:    raw,
				params: params,
				source: source,
			})
		}
		if page.NextToken == nil || aws.ToString(page.NextToken) == "" {
			break
		}
		token = page.NextToken
	}
	return out, true, nil
}

func parseCloudTrailRaw(raw string) (map[string]interface{}, string, string) {
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return map[string]interface{}{}, "", ""
	}
	params, _ := doc["requestParameters"].(map[string]interface{})
	userARN := ""
	if user, ok := doc["userIdentity"].(map[string]interface{}); ok {
		userARN, _ = user["arn"].(string)
	}
	region, _ := doc["awsRegion"].(string)
	return params, userARN, region
}

func eventResourceNames(resources []cttypes.Resource) []string {
	out := make([]string, 0, len(resources))
	for _, r := range resources {
		if name := aws.ToString(r.ResourceName); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func attachSecretsManagerEvents(drafts map[string]*secretDraft, events []collectedEvent) {
	highConfidence := map[string]map[string]bool{}
	friendlyNames := map[string]map[string]bool{}
	addIdentifier := func(index map[string]map[string]bool, ident, arn string) {
		if ident == "" {
			return
		}
		if index[ident] == nil {
			index[ident] = map[string]bool{}
		}
		index[ident][arn] = true
	}
	for arn, d := range drafts {
		addIdentifier(highConfidence, arn, arn)
		id := secretIDFromARN(arn)
		addIdentifier(highConfidence, id, arn)
		if without := secretNameWithoutSuffix(id); without != "" {
			addIdentifier(friendlyNames, without, arn)
		}
		if d.name != "" {
			addIdentifier(friendlyNames, d.name, arn)
		}
	}
	seen := map[string]bool{}
	for _, event := range events {
		// Substring matching against event.Raw is deliberate: many Secrets Manager
		// CloudTrail events carry the secret identifier inside requestParameters more
		// reliably than the structured Resources list.
		matched := map[string]bool{}
		for ident, arns := range highConfidence {
			if !strings.Contains(event.raw, ident) {
				continue
			}
			for arn := range arns {
				matched[arn] = true
			}
		}
		if len(matched) == 0 {
			for ident, arns := range friendlyNames {
				if !strings.Contains(event.raw, ident) {
					continue
				}
				for arn := range arns {
					matched[arn] = true
				}
			}
		}
		for arn := range matched {
			key := event.normalized.EventID + "\x00" + arn
			if seen[key] {
				continue
			}
			seen[key] = true
			d := drafts[arn]
			d.dynamic["cloudtrail_events"] = appendNormalizedEvent(d.dynamic["cloudtrail_events"], event.normalized)
			if event.normalized.EventName == "DeleteSecret" {
				// DescribeSecret exposes DeletedDate but not the original recovery window.
				// When CloudTrail has the DeleteSecret request, use its request parameter.
				if days := recoveryWindowDays(event.params); days > 0 {
					d.config["recovery_window_days"] = days
				}
			}
		}
	}
}

func attachIAMCredentialEvents(drafts map[string]*secretDraft, events []collectedEvent) {
	for _, event := range events {
		affected := affectedIAMIdentifiers(event.params)
		if len(affected) == 0 {
			continue
		}
		for _, d := range drafts {
			// IAM credential-removal events are account-wide. We attribute them only
			// when the affected user/role identifier appears in a resource-policy
			// principal string, and otherwise drop the event.
			if principalsMatchAffected(d.principal, affected) {
				d.dynamic["iam_credential_removal_events"] = appendNormalizedEvent(d.dynamic["iam_credential_removal_events"], event.normalized)
			}
		}
	}
}

func appendNormalizedEvent(current interface{}, event normalizedEvent) []normalizedEvent {
	switch t := current.(type) {
	case []normalizedEvent:
		return append(t, event)
	default:
		return []normalizedEvent{event}
	}
}

func recoveryWindowDays(params map[string]interface{}) int {
	for _, key := range []string{"recoveryWindowInDays", "RecoveryWindowInDays"} {
		switch v := params[key].(type) {
		case float64:
			return int(v)
		case int:
			return v
		}
	}
	return 0
}

func affectedIAMIdentifiers(params map[string]interface{}) []string {
	keys := []string{"userName", "roleName", "userArn", "roleArn"}
	out := []string{}
	for _, key := range keys {
		if v, ok := params[key].(string); ok && v != "" {
			out = append(out, v)
		}
	}
	return out
}

func principalsMatchAffected(principals, affected []string) bool {
	for _, principal := range principals {
		for _, ident := range affected {
			if principal != "" && ident != "" && strings.Contains(principal, ident) {
				return true
			}
		}
	}
	return false
}
