package main

import (
	"encoding/json"
	"fmt"
	"strconv"
)

const (
	defaultLookbackDays = 90 // default window for cloudtrail.LookupEvents
	maxLookbackDays     = 90 // hard cap; CloudTrail event-history supports up to 90 days
)

type PluginConfig struct {
	Accounts       []AccountConfig
	DefaultRegions []string
	LookbackDays   int
	PolicyInputs   map[string]interface{}
	PolicyLabels   map[string]string
	MaxConcurrency int
	// APITimeoutSeconds bounds the entire per-target collection across all paginated AWS calls.
	APITimeoutSeconds int
}

type AccountConfig struct {
	AccountID   string            `json:"account_id"`
	Regions     []string          `json:"regions"`
	RoleARN     string            `json:"role_arn"`
	ExternalID  string            `json:"external_id"`
	SessionName string            `json:"session_name"`
	Tags        map[string]string `json:"tags"`
}

func parsePluginConfig(raw map[string]string) (*PluginConfig, error) {
	cfg := &PluginConfig{
		Accounts:          []AccountConfig{},
		DefaultRegions:    []string{},
		LookbackDays:      defaultLookbackDays,
		PolicyInputs:      map[string]interface{}{},
		PolicyLabels:      map[string]string{},
		MaxConcurrency:    4,
		APITimeoutSeconds: 120,
	}
	if raw == nil {
		return cfg, nil
	}
	if v, ok := raw["accounts"]; ok && v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.Accounts); err != nil {
			return nil, fmt.Errorf("parse accounts: %w", err)
		}
	}
	if v, ok := raw["default_regions"]; ok && v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.DefaultRegions); err != nil {
			return nil, fmt.Errorf("parse default_regions: %w", err)
		}
	}
	if v, ok := raw["lookback_days"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("parse lookback_days: %w", err)
		}
		cfg.LookbackDays = n
	}
	if cfg.LookbackDays <= 0 {
		return nil, fmt.Errorf("lookback_days must be positive")
	}
	if cfg.LookbackDays > maxLookbackDays {
		return nil, fmt.Errorf("lookback_days must be <= %d", maxLookbackDays)
	}
	policyInputKey := "policy_inputs"
	if _, ok := raw[policyInputKey]; !ok {
		policyInputKey = "policy_input"
	}
	if v, ok := raw[policyInputKey]; ok && v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.PolicyInputs); err != nil {
			return nil, fmt.Errorf("parse %s: %w", policyInputKey, err)
		}
	}
	if v, ok := raw["policy_labels"]; ok && v != "" {
		if err := json.Unmarshal([]byte(v), &cfg.PolicyLabels); err != nil {
			return nil, fmt.Errorf("parse policy_labels: %w", err)
		}
	}
	if v, ok := raw["max_concurrency"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("parse max_concurrency: %w", err)
		}
		cfg.MaxConcurrency = n
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 1
	}
	if v, ok := raw["api_timeout_seconds"]; ok && v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("parse api_timeout_seconds: %w", err)
		}
		cfg.APITimeoutSeconds = n
	}
	if cfg.APITimeoutSeconds <= 0 {
		return nil, fmt.Errorf("api_timeout_seconds must be positive")
	}
	for i := range cfg.Accounts {
		if cfg.Accounts[i].Tags == nil {
			cfg.Accounts[i].Tags = map[string]string{}
		}
	}
	return cfg, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// clonePolicyInputs intentionally performs only a shallow top-level copy.
// Nested maps/slices remain shared; callers must deep-copy nested values before mutating.
func clonePolicyInputs(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
