package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func generateTestRSAKey(t *testing.T) (string, *rsa.PrivateKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM), privateKey
}

type testServer struct {
	t              *testing.T
	server         *httptest.Server
	expectedTokens map[string]bool
	claims         *jwt.Claims
}

func newTestServer(t *testing.T) *testServer {
	ts := &testServer{
		t:              t,
		expectedTokens: make(map[string]bool),
	}

	ts.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/v1/token":
			ts.handleToken(w, r)
		case "/oauth2/v1/authorize":
			ts.handleAuthorize(w, r)
		default:
			http.NotFound(w, r)
		}
	}))

	return ts
}

func (ts *testServer) handleToken(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	require.NoError(ts.t, err)

	grantType := r.Form.Get("grant_type")
	switch grantType {
	case "client_credentials":
		ts.handleClientCredentials(w, r)
	case "authorization_code":
		ts.handleAuthCode(w, r)
	case "refresh_token":
		ts.handleRefreshToken(w, r)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		ts.handleTokenExchange(w, r)
	default:
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
	}
}

func (ts *testServer) handleClientCredentials(w http.ResponseWriter, r *http.Request) {
	if assertionType := r.Form.Get("client_assertion_type"); assertionType != "" {
		// JWT authentication
		assertion := r.Form.Get("client_assertion")
		if assertion == "" {
			http.Error(w, "invalid_client", http.StatusUnauthorized)
			return
		}
		// Validate JWT here if needed
	} else {
		// Client secret authentication
		clientID := r.Form.Get("client_id")
		clientSecret := r.Form.Get("client_secret")
		if clientID != "test-client" || clientSecret != "test-secret" {
			http.Error(w, "invalid_client", http.StatusUnauthorized)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"access_token": "test-access-token",
		"token_type": "Bearer",
		"expires_in": 3600
	}`)
}

func (ts *testServer) handleAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	if code != "valid-code" {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"access_token": "test-access-token",
		"refresh_token": "test-refresh-token",
		"token_type": "Bearer",
		"expires_in": 3600
	}`)
}

func (ts *testServer) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Form.Get("refresh_token")
	if refreshToken != "test-refresh-token" {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"access_token": "new-access-token",
		"refresh_token": "new-refresh-token",
		"token_type": "Bearer",
		"expires_in": 3600
	}`)
}

func (ts *testServer) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	subjectToken := r.Form.Get("subject_token")
	if subjectToken != "test-access-token" {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{
		"access_token": "exchanged-access-token",
		"token_type": "Bearer",
		"expires_in": 3600
	}`)
}

func (ts *testServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	if clientID != "test-client" {
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	require.NoError(ts.t, err)

	q := redirectURL.Query()
	q.Set("code", "valid-code")
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (ts *testServer) Close() {
	ts.server.Close()
}

func TestOktaProvider(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	domain := strings.TrimPrefix(ts.server.URL, "http://")
	keyPEM, _ := generateTestRSAKey(t)

	tests := []struct {
		name    string
		setup   func() (Provider, error)
		test    func(t *testing.T, p Provider)
		wantErr bool
	}{
		{
			name: "create provider with client secret",
			setup: func() (Provider, error) {
				return OktaFactory(context.Background(), OktaProviderV1, map[string]string{
					"domain": domain,
					"scheme": "http", // Add this for test
				})
			},
			test: func(t *testing.T, p Provider) {
				ops := p.Private("test-client", "test-secret")
				require.NotNil(t, ops)

				// Test client credentials
				tok, err := ops.ClientCredentials(context.Background())
				require.NoError(t, err)
				assert.Equal(t, "test-access-token", tok.AccessToken)
				assert.Equal(t, "Bearer", tok.TokenType)
			},
		},
		{
			name: "create provider with private key",
			setup: func() (Provider, error) {
				return OktaFactory(context.Background(), OktaProviderV1, map[string]string{
					"domain":      domain,
					"private_key": keyPEM,
					"scheme":      "http", // Add this for test
				})
			},
			test: func(t *testing.T, p Provider) {
				ops := p.Private("test-client", "")
				require.NotNil(t, ops)

				// Test client credentials with JWT
				tok, err := ops.ClientCredentials(context.Background())
				require.NoError(t, err)
				assert.Equal(t, "test-access-token", tok.AccessToken)
				assert.Equal(t, "Bearer", tok.TokenType)
			},
		},
		{
			name: "auth code flow",
			setup: func() (Provider, error) {
				return OktaFactory(context.Background(), OktaProviderV1, map[string]string{
					"domain": domain,
					"scheme": "http", // Add this for test
				})
			},
			test: func(t *testing.T, p Provider) {
				ops := p.Private("test-client", "test-secret")
				require.NotNil(t, ops)

				// Test auth code URL generation
				authURL, ok := ops.AuthCodeURL("test-state", WithRedirectURL("http://localhost/callback"))
				require.True(t, ok)
				assert.Contains(t, authURL, "/oauth2/v1/authorize")
				assert.Contains(t, authURL, "client_id=test-client")
				assert.Contains(t, authURL, "state=test-state")

				// Test auth code exchange
				tok, err := ops.AuthCodeExchange(context.Background(), "valid-code",
					WithRedirectURL("http://localhost/callback"))
				require.NoError(t, err)
				assert.Equal(t, "test-access-token", tok.AccessToken)
				assert.Equal(t, "test-refresh-token", tok.RefreshToken)
			},
		},
		{
			name: "refresh token",
			setup: func() (Provider, error) {
				return OktaFactory(context.Background(), OktaProviderV1, map[string]string{
					"domain": domain,
					"scheme": "http", // Add this for test
				})
			},
			test: func(t *testing.T, p Provider) {
				ops := p.Private("test-client", "test-secret")
				require.NotNil(t, ops)

				oldToken := &Token{
					Token: &oauth2.Token{
						AccessToken:  "test-access-token",
						RefreshToken: "test-refresh-token",
						TokenType:    "Bearer",
					},
					ProviderVersion: OktaProviderV1,
				}

				// Test refresh token
				newToken, err := ops.RefreshToken(context.Background(), oldToken)
				require.NoError(t, err)
				assert.Equal(t, "new-access-token", newToken.AccessToken)
				assert.Equal(t, "new-refresh-token", newToken.RefreshToken)
			},
		},
		{
			name: "token exchange",
			setup: func() (Provider, error) {
				return OktaFactory(context.Background(), OktaProviderV1, map[string]string{
					"domain": domain,
					"scheme": "http", // Add this for test
				})
			},
			test: func(t *testing.T, p Provider) {
				ops := p.Private("test-client", "test-secret")
				require.NotNil(t, ops)

				oldToken := &Token{
					Token: &oauth2.Token{
						AccessToken: "test-access-token",
						TokenType:   "Bearer",
					},
					ProviderVersion: OktaProviderV1,
				}

				// Test token exchange
				newToken, err := ops.TokenExchange(context.Background(), oldToken)
				require.NoError(t, err)
				assert.Equal(t, "exchanged-access-token", newToken.AccessToken)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.setup()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, p)

			tt.test(t, p)
		})
	}
}
