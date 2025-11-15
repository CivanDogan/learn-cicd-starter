package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectError bool
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey: "my-secret-key",
			expectError: false,
		},
		{
			name: "valid API key with multiple parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey key-with-dashes-123"},
			},
			expectedKey: "key-with-dashes-123",
			expectError: false,
		},
		{
			name:        "no authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "malformed header - only ApiKey without key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectError: true,
		},
		{
			name: "malformed header - no space",
			headers: http.Header{
				"Authorization": []string{"ApiKeymy-key"},
			},
			expectedKey: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectError {
				if err == nil {
					t.Errorf("GetAPIKey() expected an error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("GetAPIKey() unexpected error = %v", err)
				}
			}

			if key != tt.expectedKey {
				t.Errorf("GetAPIKey() key = %v, want %v", key, tt.expectedKey)
			}
		})
	}
}
