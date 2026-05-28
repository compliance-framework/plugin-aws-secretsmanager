package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/go-hclog"
)

type fakeFactory struct {
	targets []ResolvedTarget
	set     AWSClientSet
}

func (f fakeFactory) ResolveTargets(context.Context, *PluginConfig) ([]ResolvedTarget, error) {
	return f.targets, nil
}

func (f fakeFactory) ClientsForTarget(context.Context, ResolvedTarget) (AWSClientSet, error) {
	return f.set, nil
}

type fakeSTS struct{}

func (fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String("123456789012")}, nil
}

type fakeSM struct {
	mu              sync.Mutex
	listPages       []*sm.ListSecretsOutput
	listErr         error
	describes       map[string]*sm.DescribeSecretOutput
	policies        map[string]*sm.GetResourcePolicyOutput
	policyErrs      map[string]error
	versionPages    map[string][]*sm.ListSecretVersionIdsOutput
	describeCalls   map[string]int
	policyCalls     map[string]int
	versionCalls    map[string]int
	listSecretCalls int
}

func (f *fakeSM) ListSecrets(context.Context, *sm.ListSecretsInput, ...func(*sm.Options)) (*sm.ListSecretsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listSecretCalls++
	if f.listErr != nil {
		return nil, f.listErr
	}
	idx := f.listSecretCalls - 1
	if idx >= len(f.listPages) {
		return &sm.ListSecretsOutput{}, nil
	}
	return f.listPages[idx], nil
}

func (f *fakeSM) DescribeSecret(_ context.Context, in *sm.DescribeSecretInput, _ ...func(*sm.Options)) (*sm.DescribeSecretOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arn := aws.ToString(in.SecretId)
	f.describeCalls[arn]++
	return f.describes[arn], nil
}

func (f *fakeSM) GetResourcePolicy(_ context.Context, in *sm.GetResourcePolicyInput, _ ...func(*sm.Options)) (*sm.GetResourcePolicyOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arn := aws.ToString(in.SecretId)
	f.policyCalls[arn]++
	if err := f.policyErrs[arn]; err != nil {
		return nil, err
	}
	return f.policies[arn], nil
}

func (f *fakeSM) ListSecretVersionIds(_ context.Context, in *sm.ListSecretVersionIdsInput, _ ...func(*sm.Options)) (*sm.ListSecretVersionIdsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	arn := aws.ToString(in.SecretId)
	f.versionCalls[arn]++
	pages := f.versionPages[arn]
	idx := f.versionCalls[arn] - 1
	if idx >= len(pages) {
		return &sm.ListSecretVersionIdsOutput{}, nil
	}
	return pages[idx], nil
}

type fakeCT struct {
	events map[string][]cttypes.Event
}

func (f fakeCT) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	source := aws.ToString(in.LookupAttributes[0].AttributeValue)
	return &cloudtrail.LookupEventsOutput{Events: f.events[source]}, nil
}

func TestCollectorCollectsSecretShapeAndCloudTrail(t *testing.T) {
	arn1 := "arn:aws:secretsmanager:us-east-1:123456789012:secret:MyApp/db-AbCdEf"
	arn2 := "arn:aws:secretsmanager:us-east-1:123456789012:secret:Vendor/key-GhIjKl"
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	smFake := &fakeSM{
		listPages: []*sm.ListSecretsOutput{
			{SecretList: []smtypes.SecretListEntry{{ARN: aws.String(arn1)}}, NextToken: aws.String("next")},
			{SecretList: []smtypes.SecretListEntry{{ARN: aws.String(arn2)}}},
		},
		describes: map[string]*sm.DescribeSecretOutput{
			arn1: {
				ARN: aws.String(arn1), Name: aws.String("MyApp/db-AbCdEf"), Description: aws.String("db secret"),
				KmsKeyId: aws.String(""), RotationEnabled: aws.Bool(false), LastChangedDate: aws.Time(now),
				Tags:              []smtypes.Tag{{Key: aws.String("DataClassification"), Value: aws.String("confidential")}},
				ReplicationStatus: []smtypes.ReplicationStatusType{{Region: aws.String("us-west-2"), Status: smtypes.StatusTypeInSync, LastAccessedDate: aws.Time(now)}},
			},
			arn2: {ARN: aws.String(arn2), Name: aws.String("Vendor/key-GhIjKl"), KmsKeyId: aws.String("kms-key")},
		},
		policies: map[string]*sm.GetResourcePolicyOutput{
			arn1: {ResourcePolicy: aws.String(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/app-reader"},"Action":["secretsmanager:GetSecretValue"]}}`)},
			arn2: {ResourcePolicy: aws.String("")},
		},
		policyErrs: map[string]error{
			arn2: &smtypes.ResourceNotFoundException{Message: aws.String("none")},
		},
		versionPages: map[string][]*sm.ListSecretVersionIdsOutput{
			arn1: {
				{Versions: []smtypes.SecretVersionsListEntry{{VersionId: aws.String("v1"), CreatedDate: aws.Time(now), VersionStages: []string{"AWSCURRENT"}, KmsKeyIds: []string{"k1"}}}, NextToken: aws.String("next")},
				{Versions: []smtypes.SecretVersionsListEntry{{VersionId: aws.String("v0"), CreatedDate: aws.Time(now.Add(-time.Hour)), VersionStages: []string{}, KmsKeyIds: []string{"k0"}}}},
			},
			arn2: {{Versions: []smtypes.SecretVersionsListEntry{{VersionId: aws.String("v2"), VersionStages: []string{"AWSPREVIOUS"}}}}},
		},
		describeCalls: map[string]int{}, policyCalls: map[string]int{}, versionCalls: map[string]int{},
	}
	ctFake := fakeCT{events: map[string][]cttypes.Event{
		"secretsmanager.amazonaws.com": {{
			EventName: aws.String("RotateSecret"), EventId: aws.String("evt-1"), EventTime: aws.Time(now),
			CloudTrailEvent: aws.String(`{"eventSource":"secretsmanager.amazonaws.com","eventName":"RotateSecret","awsRegion":"us-east-1","userIdentity":{"arn":"arn:aws:iam::123456789012:role/rotation"},"requestParameters":{"secretId":"` + arn1 + `"}}`),
		}},
		"iam.amazonaws.com": {{
			EventName: aws.String("DeleteAccessKey"), EventId: aws.String("evt-2"), EventTime: aws.Time(now),
			CloudTrailEvent: aws.String(`{"eventSource":"iam.amazonaws.com","eventName":"DeleteAccessKey","awsRegion":"us-east-1","userIdentity":{"arn":"arn:aws:iam::123456789012:role/admin"},"requestParameters":{"userName":"app-reader"}}`),
		}},
	}}
	cfg := &PluginConfig{LookbackDays: 90, MaxConcurrency: 1, APITimeoutSeconds: 30, PolicyInputs: map[string]interface{}{}}
	collector := &Collector{Logger: hclog.NewNullLogger(), Config: cfg, Factory: fakeFactory{
		targets: []ResolvedTarget{{AccountID: "123456789012", Region: "us-east-1"}},
		set:     AWSClientSet{SecretsManager: smFake, CloudTrail: ctFake, STS: fakeSTS{}},
	}}
	result := collector.Collect(context.Background())
	if result.Err != nil {
		t.Fatalf("collect: %v", result.Err)
	}
	if len(result.Records) != 2 {
		t.Fatalf("records = %d", len(result.Records))
	}
	if smFake.listSecretCalls != 2 || smFake.describeCalls[arn1] != 1 || smFake.policyCalls[arn1] != 1 || smFake.versionCalls[arn1] != 2 {
		t.Fatalf("unexpected call counts: list=%d describe=%d policy=%d versions=%d", smFake.listSecretCalls, smFake.describeCalls[arn1], smFake.policyCalls[arn1], smFake.versionCalls[arn1])
	}
	rec := result.Records[0]
	if rec.Input.Config["kms_key_id"] != "aws/secretsmanager" {
		t.Fatalf("default kms sentinel missing: %v", rec.Input.Config["kms_key_id"])
	}
	if rec.Input.Config["deprecated_version_count"].(int) != 1 {
		t.Fatalf("deprecated count = %v", rec.Input.Config["deprecated_version_count"])
	}
	if got := rec.Input.Config["replication_status"].([]map[string]interface{})[0]["region"]; got != "us-west-2" {
		t.Fatalf("replication region = %v", got)
	}
	if len(rec.Input.Dynamic["cloudtrail_events"].([]normalizedEvent)) != 1 {
		t.Fatalf("secretsmanager event not attached")
	}
	if len(rec.Input.Dynamic["iam_credential_removal_events"].([]normalizedEvent)) != 1 {
		t.Fatalf("iam event not attached")
	}
	if rec.Labels["resource_id"] != "MyApp/db-AbCdEf" {
		t.Fatalf("resource id stripped suffix: %s", rec.Labels["resource_id"])
	}
}

func TestCollectorErrorScoping(t *testing.T) {
	arn := "arn:aws:secretsmanager:us-east-1:123456789012:secret:One-AbCdEf"
	t.Run("target list failure once", func(t *testing.T) {
		smFake := &fakeSM{listErr: errors.New("boom"), describeCalls: map[string]int{}, policyCalls: map[string]int{}, versionCalls: map[string]int{}}
		cfg := &PluginConfig{LookbackDays: 90, MaxConcurrency: 1, APITimeoutSeconds: 30, PolicyInputs: map[string]interface{}{}}
		result := (&Collector{Config: cfg, Factory: fakeFactory{targets: []ResolvedTarget{{AccountID: "123", Region: "us-east-1"}}, set: AWSClientSet{SecretsManager: smFake, CloudTrail: fakeCT{}, STS: fakeSTS{}}}}).Collect(context.Background())
		if len(result.Errors["target"]) != 1 {
			t.Fatalf("target errors = %d", len(result.Errors["target"]))
		}
		if len(result.Errors) != 1 {
			t.Fatalf("unexpected scoped errors: %#v", result.Errors)
		}
	})
	t.Run("per secret policy failure only on arn", func(t *testing.T) {
		smFake := &fakeSM{
			listPages:     []*sm.ListSecretsOutput{{SecretList: []smtypes.SecretListEntry{{ARN: aws.String(arn)}}}},
			describes:     map[string]*sm.DescribeSecretOutput{arn: {ARN: aws.String(arn), Name: aws.String("One-AbCdEf")}},
			policyErrs:    map[string]error{arn: errors.New("policy denied")},
			policies:      map[string]*sm.GetResourcePolicyOutput{},
			versionPages:  map[string][]*sm.ListSecretVersionIdsOutput{arn: {{}}},
			describeCalls: map[string]int{}, policyCalls: map[string]int{}, versionCalls: map[string]int{},
		}
		cfg := &PluginConfig{LookbackDays: 90, MaxConcurrency: 1, APITimeoutSeconds: 30, PolicyInputs: map[string]interface{}{}}
		result := (&Collector{Config: cfg, Factory: fakeFactory{targets: []ResolvedTarget{{AccountID: "123", Region: "us-east-1"}}, set: AWSClientSet{SecretsManager: smFake, CloudTrail: fakeCT{}, STS: fakeSTS{}}}}).Collect(context.Background())
		if len(result.Errors["target"]) != 0 {
			t.Fatalf("target errors should be empty: %#v", result.Errors["target"])
		}
		if len(result.Errors[arn]) != 1 || !strings.Contains(result.Errors[arn][0].Error(), "policy denied") {
			t.Fatalf("arn errors = %#v", result.Errors[arn])
		}
	})
}

func TestCollectorMaxConcurrencyZeroDoesNotHang(t *testing.T) {
	cfg := &PluginConfig{LookbackDays: 90, MaxConcurrency: 0, APITimeoutSeconds: 1, PolicyInputs: map[string]interface{}{}}
	smFake := &fakeSM{listPages: []*sm.ListSecretsOutput{{}}, describeCalls: map[string]int{}, policyCalls: map[string]int{}, versionCalls: map[string]int{}}
	done := make(chan struct{})
	go func() {
		(&Collector{Config: cfg, Factory: fakeFactory{targets: []ResolvedTarget{{AccountID: "123", Region: "us-east-1"}}, set: AWSClientSet{SecretsManager: smFake, CloudTrail: fakeCT{}, STS: fakeSTS{}}}}).Collect(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("collector hung with MaxConcurrency=0")
	}
}
