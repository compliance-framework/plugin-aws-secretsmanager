package main

import (
	"context"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type emptySM struct{}

func (emptySM) ListSecrets(context.Context, *sm.ListSecretsInput, ...func(*sm.Options)) (*sm.ListSecretsOutput, error) {
	return &sm.ListSecretsOutput{}, nil
}
func (emptySM) DescribeSecret(context.Context, *sm.DescribeSecretInput, ...func(*sm.Options)) (*sm.DescribeSecretOutput, error) {
	return &sm.DescribeSecretOutput{}, nil
}
func (emptySM) GetResourcePolicy(context.Context, *sm.GetResourcePolicyInput, ...func(*sm.Options)) (*sm.GetResourcePolicyOutput, error) {
	return &sm.GetResourcePolicyOutput{}, nil
}
func (emptySM) ListSecretVersionIds(context.Context, *sm.ListSecretVersionIdsInput, ...func(*sm.Options)) (*sm.ListSecretVersionIdsOutput, error) {
	return &sm.ListSecretVersionIdsOutput{}, nil
}

type emptyCT struct{}

func (emptyCT) LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return &cloudtrail.LookupEventsOutput{}, nil
}

func TestEvalNilRequest(t *testing.T) {
	p := &CompliancePlugin{logger: hclog.NewNullLogger()}
	resp, err := p.Eval(nil, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if resp.GetStatus() != proto.ExecutionStatus_FAILURE {
		t.Fatalf("status = %v", resp.GetStatus())
	}
}

func TestConfigureEvalConcurrent(t *testing.T) {
	p := &CompliancePlugin{
		logger: hclog.NewNullLogger(),
		factory: fakeFactory{
			targets: []ResolvedTarget{{AccountID: "123456789012", Region: "us-east-1"}},
			set:     AWSClientSet{SecretsManager: emptySM{}, CloudTrail: emptyCT{}, STS: fakeSTS{}},
		},
	}
	if _, err := p.Configure(&proto.ConfigureRequest{Config: map[string]string{"policy_inputs": `{"x":1}`}}); err != nil {
		t.Fatalf("configure: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp, err := p.Eval(&proto.EvalRequest{}, nil); err != nil || resp.GetStatus() != proto.ExecutionStatus_SUCCESS {
				t.Errorf("eval resp=%v err=%v", resp, err)
			}
		}()
	}
	wg.Wait()
}
