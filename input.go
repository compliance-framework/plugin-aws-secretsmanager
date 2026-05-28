package main

import (
	"strings"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
)

const (
	sourceName         = "aws-secretsmanager"
	schemaVersionV1    = "v1"
	resourceTypeSecret = "secret"
)

type AccountContext struct {
	AccountID string            `json:"account_id"`
	RoleARN   string            `json:"role_arn,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
}

type RegionContext struct {
	Name string `json:"name"`
}

type ResourceIdentity struct {
	ID   string `json:"id"`
	ARN  string `json:"arn"`
	Type string `json:"type"`
}

type Window struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type CollectionError struct {
	Scope   string `json:"scope"`
	Message string `json:"message"`
}

type CollectionMetadata struct {
	CollectedAt      string            `json:"collected_at"`
	CollectorVersion string            `json:"collector_version"`
	CollectionType   string            `json:"collection_type"`
	Errors           []CollectionError `json:"errors"`
	RawPayloadHashes map[string]string `json:"raw_payload_hashes,omitempty"`
	LookbackWindow   *Window           `json:"lookback_window,omitempty"`
}

type NormalizedInput struct {
	SchemaVersion string                 `json:"schema_version"`
	Source        string                 `json:"source"`
	Account       AccountContext         `json:"account"`
	Region        RegionContext          `json:"region"`
	Resource      ResourceIdentity       `json:"resource"`
	Config        map[string]interface{} `json:"config"`
	Dynamic       map[string]interface{} `json:"dynamic"`
	Tags          map[string]string      `json:"tags"`
	Collection    CollectionMetadata     `json:"collection"`
	PolicyInputs  map[string]interface{} `json:"policy_inputs"`
}

type ResourceRecord struct {
	Input       NormalizedInput
	Labels      map[string]string
	SubjectID   string
	SubjectType proto.SubjectType
	Title       string
	Raw         interface{}
}

func newSecretRecord(target ResolvedTarget, arn string, config map[string]interface{}, dynamic map[string]interface{}, tags map[string]string, errors []CollectionError, hashes map[string]string, lookback *Window, policyInputs map[string]interface{}, cloudTrailCollected bool, collectedAt time.Time) *ResourceRecord {
	id := secretIDFromARN(arn)
	collectionType := "config"
	if cloudTrailCollected {
		collectionType = "config_dynamic"
	}
	labels := map[string]string{
		"provider":      "aws",
		"type":          "secretsmanager",
		"subject":       "aws-secretsmanager-secret",
		"account_id":    target.AccountID,
		"region":        target.Region,
		"resource_id":   id,
		"resource_arn":  arn,
		"resource_type": resourceTypeSecret,
	}
	for k, v := range target.Tags {
		labels["account_tag_"+k] = v
	}
	input := NormalizedInput{
		SchemaVersion: schemaVersionV1,
		Source:        sourceName,
		Account: AccountContext{
			AccountID: target.AccountID,
			RoleARN:   target.RoleARN,
			Tags:      target.Tags,
		},
		Region:   RegionContext{Name: target.Region},
		Resource: ResourceIdentity{ID: id, ARN: arn, Type: resourceTypeSecret},
		Config:   config,
		Dynamic:  dynamic,
		Tags:     tags,
		Collection: CollectionMetadata{
			CollectedAt:      collectedAt.UTC().Format(time.RFC3339),
			CollectorVersion: sourceName,
			CollectionType:   collectionType,
			Errors:           errors,
			RawPayloadHashes: hashes,
			LookbackWindow:   lookback,
		},
		PolicyInputs: clonePolicyInputs(policyInputs),
	}
	return &ResourceRecord{
		Input:       input,
		Labels:      labels,
		SubjectID:   target.AccountID + ":" + target.Region + ":" + arn,
		SubjectType: proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
		Title:       "Secrets Manager secret " + id,
		Raw:         config,
	}
}

func secretIDFromARN(arn string) string {
	if idx := strings.LastIndex(arn, ":"); idx >= 0 && idx+1 < len(arn) {
		return arn[idx+1:]
	}
	return arn
}

func secretNameWithoutSuffix(id string) string {
	if len(id) > 7 && id[len(id)-7] == '-' {
		return id[:len(id)-7]
	}
	return id
}
