package main

import "testing"

func TestParsePluginConfigDefaults(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{})
	if err != nil {
		t.Fatalf("parse defaults: %v", err)
	}
	if cfg.LookbackDays != defaultLookbackDays {
		t.Fatalf("lookback = %d", cfg.LookbackDays)
	}
	if cfg.MaxConcurrency != 4 {
		t.Fatalf("max concurrency = %d", cfg.MaxConcurrency)
	}
	if cfg.APITimeoutSeconds != 120 {
		t.Fatalf("timeout = %d", cfg.APITimeoutSeconds)
	}
}

func TestParsePluginConfigValidation(t *testing.T) {
	tests := map[string]map[string]string{
		"lookback zero":             {"lookback_days": "0"},
		"lookback over max":         {"lookback_days": "91"},
		"malformed accounts":        {"accounts": "{bad"},
		"malformed policy_inputs":   {"policy_inputs": "{bad"},
		"malformed policy_labels":   {"policy_labels": "{bad"},
		"bad api timeout":           {"api_timeout_seconds": "0"},
		"non-numeric concurrency":   {"max_concurrency": "x"},
		"non-numeric lookback":      {"lookback_days": "x"},
		"malformed default regions": {"default_regions": "{bad"},
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePluginConfig(raw); err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestParsePluginConfigStructuredValues(t *testing.T) {
	cfg, err := parsePluginConfig(map[string]string{
		"accounts":        `[{"account_id":"123","regions":["us-east-1"],"tags":{"environment":"prod"}}]`,
		"default_regions": `["us-west-2"]`,
		"policy_input":    `{"minimum":30}`,
		"policy_labels":   `{"team":"security"}`,
		"max_concurrency": "0",
	})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.MaxConcurrency != 1 {
		t.Fatalf("zero concurrency should normalize to 1, got %d", cfg.MaxConcurrency)
	}
	if cfg.Accounts[0].Tags["environment"] != "prod" {
		t.Fatalf("account tags not parsed")
	}
	if cfg.PolicyInputs["minimum"].(float64) != 30 {
		t.Fatalf("policy input not parsed")
	}
	if cfg.PolicyLabels["team"] != "security" {
		t.Fatalf("policy labels not parsed")
	}
}
