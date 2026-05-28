package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

func MergeMaps(a, b map[string]string) map[string]string {
	out := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func StringAddressed(v string) *string {
	return &v
}

func FormatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func Sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func HashString(v string) string {
	return Sha256Hex([]byte(v))
}

func StringValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func BoolValue(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

func Int64Value(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

func ErrorString(scope string, err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%s: %v", scope, err)
}
