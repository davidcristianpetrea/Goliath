package config

import (
	"os"
	"strings"
)

// EnvOr returns the first non-empty trimmed environment variable among primary
// (GOLIATH_*) and legacy (ARTEX_*), allowing seamless migration without breaking
// existing deployments.
func EnvOr(primary, legacy string) string {
	if v := strings.TrimSpace(os.Getenv(primary)); v != "" {
		return v
	}
	if legacy != "" {
		return strings.TrimSpace(os.Getenv(legacy))
	}
	return ""
}

// EnvBool reports whether either primary or legacy env var is set to a truthy
// value ("1", "true", "yes", "on").
func EnvBool(primary, legacy string) bool {
	v := strings.ToLower(EnvOr(primary, legacy))
	switch v {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
