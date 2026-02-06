package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-key-123"},
			},
			want:    "secret-key-123",
			wantErr: nil,
		},
		{
			name:    "missing Authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed - no ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer invalid"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed - single part",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
