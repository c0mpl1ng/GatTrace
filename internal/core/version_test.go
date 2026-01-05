package core

import (
	"testing"
)

func TestValidateSemanticVersion(t *testing.T) {
	validVersions := []string{
		"v1.0.0",
		"1.0.0",
		"v2.1.3",
		"0.1.0",
		"v1.0.0-alpha",
		"v1.0.0-alpha.1",
		"v1.0.0+build.1",
		"v1.0.0-alpha+build.1",
		"10.20.30",
	}

	for _, version := range validVersions {
		t.Run("valid_"+version, func(t *testing.T) {
			if err := ValidateSemanticVersion(version); err != nil {
				t.Errorf("Expected version %s to be valid, got error: %v", version, err)
			}
		})
	}

	invalidVersions := []string{
		"",
		"1",
		"1.0",
		"1.0.0.0",
		"v1.0.0.0",
		"1.0.0-",
		"1.0.0+",
		"01.0.0",
		"1.01.0",
		"1.0.01",
		"invalid",
		"v1.0.0-",
		"v1.0.0+",
	}

	for _, version := range invalidVersions {
		t.Run("invalid_"+version, func(t *testing.T) {
			if err := ValidateSemanticVersion(version); err == nil {
				t.Errorf("Expected version %s to be invalid, but validation passed", version)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"1.0.0", "v1.0.0"},
		{"v1.0.0", "v1.0.0"},
		{"2.1.3", "v2.1.3"},
		{"v2.1.3", "v2.1.3"},
		{"", ""},
		{"0.1.0", "v0.1.0"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := NormalizeVersion(tc.input)
			if result != tc.expected {
				t.Errorf("NormalizeVersion(%s) = %s, expected %s", tc.input, result, tc.expected)
			}
		})
	}
}
