package utils

import (
	"regexp"
	"testing"
)

func TestGenerateCodeVerifierWithLength(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{
			name:    "invalid length min",
			length:  10,
			wantErr: true,
		},
		{
			name:    "invalid length max",
			length:  100,
			wantErr: true,
		},
		{
			name:    "valid min length",
			length:  32,
			wantErr: false,
		},
		{
			name:    "valid max length",
			length:  96,
			wantErr: false,
		},
		{
			name:    "valid length",
			length:  50,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateCodeVerifierWithLength(tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCodeVerifierWithLength() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got == nil {
					t.Errorf("GenerateCodeVerifierWithLength() = nil, value is needed")
				} else {
					verifyLengthAndPattern(got.CodeVerifier, t)
				}
			}
		})
	}
}

func TestPKCECodeVerifier_CodeChallengePlain(t *testing.T) {
	tests := []struct {
		name         string
		CodeVerifier string
		want         string
	}{
		{
			name:         "should be same as verifier",
			CodeVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
			want:         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &PKCECodeVerifier{
				CodeVerifier: tt.CodeVerifier,
			}

			if got := v.CodeChallengePlain(); got != tt.want {
				t.Errorf("PKCECodeVerifier.CodeChallengePlain() = %v, want %v", got, tt.want)
			}
		})
	}
}

// via https://tools.ietf.org/html/rfc7636#appendix-B
func TestPKCECodeVerifier_CodeChallengeS256(t *testing.T) {
	cv, _ := GenerateCodeVerifierWithLength(50)

	tests := []struct {
		name         string
		CodeVerifier string
		want         string
	}{
		{
			name:         "should be sha256 of verifier",
			CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			want:         "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		},
		{
			name:         "should be same as verifier",
			CodeVerifier: cv.CodeVerifier,
			want:         "", // since we are only verifying pattern
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &PKCECodeVerifier{
				CodeVerifier: tt.CodeVerifier,
			}
			got := v.CodeChallengeS256()
			if tt.want != "" && got != tt.want {
				t.Errorf("PKCECodeVerifier.CodeChallengeS256() = %v, want %v", got, tt.want)
			}
			verifyLengthAndPattern(got, t)
		})
	}
}

func verifyLengthAndPattern(val string, t *testing.T) {
	if len(val) < 43 || len(val) > 128 {
		t.Errorf("Invalid length: %v", val)
	}
	if _, e := regexp.Match(`[a-zA-Z0-9-_.~]+`, []byte(val)); e != nil {
		t.Errorf("Invalid pattern: %v", val)
	}
}
