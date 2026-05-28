package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

func TestInlineRegoPoliciesAgainstSecretRecord(t *testing.T) {
	dir := t.TempDir()
	policy := `package compliance_framework.aws_secretsmanager.fixture

import future.keywords.if

title := "fixture"

violation[json.marshal({"id": "wildcard-principal", "title": "Wildcard principal"})] if {
	some p in input.config.resource_policy.principals
	p.principal == "*"
}

violation[json.marshal({"id": "rotation-disabled", "title": "Rotation disabled"})] if {
	input.config.rotation_enabled == false
	input.config.owning_service == ""
}

violation[json.marshal({"id": "confidential-default-kms", "title": "Confidential secret uses default KMS"})] if {
	input.tags.DataClassification == "confidential"
	input.config.kms_key_id == "aws/secretsmanager"
}
`
	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	record := newSecretRecord(
		ResolvedTarget{AccountID: "123456789012", Region: "us-east-1"},
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:App/db-AbCdEf",
		map[string]interface{}{
			"secret_arn":       "arn:aws:secretsmanager:us-east-1:123456789012:secret:App/db-AbCdEf",
			"kms_key_id":       "aws/secretsmanager",
			"rotation_enabled": false,
			"owning_service":   "",
			"resource_policy": map[string]interface{}{"principals": []map[string]interface{}{
				{"principal": "*", "action": []string{"secretsmanager:GetSecretValue"}, "condition": nil, "effect": "Allow"},
			}},
		},
		map[string]interface{}{"cloudtrail_events": []normalizedEvent{}, "iam_credential_removal_events": []normalizedEvent{}},
		map[string]string{"DataClassification": "confidential"},
		nil,
		map[string]string{},
		nil,
		map[string]interface{}{},
		false,
		time.Now(),
	)
	plugin := &CompliancePlugin{logger: hclog.NewNullLogger()}
	evidence, err := plugin.evaluateRecord(context.Background(), []string{dir}, record, map[string]string{}, map[string]interface{}{})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(evidence) != 1 {
		t.Fatalf("evidence count = %d", len(evidence))
	}
	if evidence[0].GetStatus().GetState() != proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED {
		t.Fatalf("state = %v", evidence[0].GetStatus().GetState())
	}
	if len(evidence[0].GetProps()) != 3 {
		t.Fatalf("violations = %d", len(evidence[0].GetProps()))
	}
}
