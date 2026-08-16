package remediation

import (
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024 * 5, "5.0 MB"},
		{1024 * 1024 * 1024 * 3, "3.0 GB"},
	}

	for _, tt := range tests {
		result := formatBytes(tt.input)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestExecuteFix_UnknownAction(t *testing.T) {
	res := ExecuteFix("non_existent_action_xyz")
	if res.Success {
		t.Errorf("Expected failure for unknown action")
	}
	if res.Title != "Okänd åtgärd" {
		t.Errorf("Expected Title 'Okänd åtgärd', got '%s'", res.Title)
	}
}
