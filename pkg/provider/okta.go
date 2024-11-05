package provider

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/puppetlabs/leg/errmap/pkg/errmark"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/clientctx"
	"github.com/puppetlabs/vault-plugin-secrets-oauthapp/v3/pkg/oauth2ext/devicecode"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	OptionDomain     = "domain"
	OptionPrivateKey = "private_key"
	OptionScheme     = "scheme" // Add this for testing

	JWTExpirationTime       = time.Hour
	JWTAssertionType        = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	JWTClientAssertionParam = "client_assertion"
	JWTAssertionTypeParam   = "client_assertion_type"

	OktaProviderV1 = 1
)

func init() {
	GlobalRegistry.MustRegister("okta", OktaFactory)
}

type oktaOperations struct {
	vsn             int
	endpointFactory EndpointFactoryFunc
	clientID        string
	clientSecret    string
	privateKey      *rsa.PrivateKey
	usePrivateKey   bool
}

func (o *oktaOperations) generateJWT() (string, error) {
	if !o.usePrivateKey || o.privateKey == nil {
		return "", fmt.Errorf("private key not configured")
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:    o.clientID,
		Subject:   o.clientID,
		Audience:  jwt.Audience{o.endpointFactory(nil).TokenURL},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(JWTExpirationTime)),
		ID:        uuid.New().String(),
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: o.privateKey},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	token, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to create JWT: %w", err)
	}

	return token, nil
}

func (o *oktaOperations) AuthCodeURL(state string, opts ...AuthCodeURLOption) (string, bool) {
	options := &AuthCodeURLOptions{}
	options.ApplyOptions(opts)

	endpoint := o.endpointFactory(options.ProviderOptions)
	if endpoint.AuthURL == "" {
		return "", false
	}

	cfg := &oauth2.Config{
		Endpoint:    endpoint.Endpoint,
		ClientID:    o.clientID,
		Scopes:      options.Scopes,
		RedirectURL: options.RedirectURL,
	}

	return cfg.AuthCodeURL(state, options.AuthCodeOptions...), true
}

func (o *oktaOperations) DeviceCodeAuth(ctx context.Context, opts ...DeviceCodeAuthOption) (*devicecode.Auth, bool, error) {
	return nil, false, nil
}

func (o *oktaOperations) DeviceCodeExchange(ctx context.Context, deviceCode string, opts ...DeviceCodeExchangeOption) (*Token, error) {
	return nil, fmt.Errorf("device code flow not supported")
}

func (o *oktaOperations) AuthCodeExchange(ctx context.Context, code string, opts ...AuthCodeExchangeOption) (*Token, error) {
	if o.clientSecret == "" && !o.usePrivateKey {
		return nil, errmark.MarkUser(ErrMissingClientSecret)
	}

	options := &AuthCodeExchangeOptions{}
	options.ApplyOptions(opts)

	endpoint := o.endpointFactory(options.ProviderOptions)

	var tok *oauth2.Token
	var err error

	if o.usePrivateKey {
		assertion, err := o.generateJWT()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT: %w", err)
		}

		cfg := &oauth2.Config{
			Endpoint:    endpoint.Endpoint,
			ClientID:    o.clientID,
			RedirectURL: options.RedirectURL,
		}

		opts := []oauth2.AuthCodeOption{
			oauth2.SetAuthURLParam(JWTAssertionTypeParam, JWTAssertionType),
			oauth2.SetAuthURLParam(JWTClientAssertionParam, assertion),
		}
		opts = append(opts, options.AuthCodeOptions...)

		tok, err = cfg.Exchange(ctx, code, opts...)
	} else {
		cfg := &oauth2.Config{
			Endpoint:     endpoint.Endpoint,
			ClientID:     o.clientID,
			ClientSecret: o.clientSecret,
			RedirectURL:  options.RedirectURL,
		}

		tok, err = cfg.Exchange(ctx, code, options.AuthCodeOptions...)
	}

	if err != nil {
		return nil, err
	}

	return &Token{
		Token:           tok,
		ProviderVersion: o.vsn,
		ProviderOptions: options.ProviderOptions,
	}, nil
}

func (o *oktaOperations) RefreshToken(ctx context.Context, t *Token, opts ...RefreshTokenOption) (*Token, error) {
	options := &RefreshTokenOptions{}
	WithProviderOptions(t.ProviderOptions).ApplyToRefreshTokenOptions(options)
	options.ApplyOptions(opts)

	endpoint := o.endpointFactory(options.ProviderOptions)

	var tok *oauth2.Token
	var err error

	if o.usePrivateKey {
		assertion, err := o.generateJWT()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT: %w", err)
		}

		cfg := &oauth2.Config{
			Endpoint: endpoint.Endpoint,
			ClientID: o.clientID,
		}

		ctx = context.WithValue(ctx, oauth2.HTTPClient, oauth2.NewClient(ctx, nil))
		ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{
			Transport: &oauth2.Transport{
				Source: oauth2.ReuseTokenSource(nil, oauth2.StaticTokenSource(&oauth2.Token{
					AccessToken: assertion,
					TokenType:   "urn:ietf:params:oauth:token-type:jwt",
				})),
			},
		})

		tok, err = cfg.TokenSource(ctx, &oauth2.Token{
			RefreshToken: t.RefreshToken,
		}).Token()
		if err != nil {
			return nil, err
		}
	} else {
		if o.clientSecret == "" {
			return nil, errmark.MarkUser(ErrMissingClientSecret)
		}

		cfg := &oauth2.Config{
			Endpoint:     endpoint.Endpoint,
			ClientID:     o.clientID,
			ClientSecret: o.clientSecret,
		}

		tok, err = cfg.TokenSource(ctx, &oauth2.Token{
			RefreshToken: t.RefreshToken,
		}).Token()
	}

	if err != nil {
		return nil, err
	}

	return &Token{
		Token:           tok,
		ProviderVersion: o.vsn,
		ProviderOptions: options.ProviderOptions,
	}, nil
}

func (o *oktaOperations) ClientCredentials(ctx context.Context, opts ...ClientCredentialsOption) (*Token, error) {
	options := &ClientCredentialsOptions{}
	options.ApplyOptions(opts)

	endpoint := o.endpointFactory(options.ProviderOptions)

	if o.usePrivateKey {
		assertion, err := o.generateJWT()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT: %w", err)
		}

		if options.EndpointParams == nil {
			options.EndpointParams = url.Values{}
		}
		options.EndpointParams.Set(JWTAssertionTypeParam, JWTAssertionType)
		options.EndpointParams.Set(JWTClientAssertionParam, assertion)

		cc := &clientcredentials.Config{
			ClientID:       o.clientID,
			TokenURL:       endpoint.TokenURL,
			Scopes:         options.Scopes,
			EndpointParams: options.EndpointParams,
			AuthStyle:      oauth2.AuthStyleInParams,
		}

		tok, err := cc.Token(ctx)
		if err != nil {
			return nil, err
		}

		return &Token{
			Token:           tok,
			ProviderVersion: o.vsn,
			ProviderOptions: options.ProviderOptions,
		}, nil
	}

	if o.clientSecret == "" {
		return nil, errmark.MarkUser(ErrMissingClientSecret)
	}

	cc := &clientcredentials.Config{
		ClientID:       o.clientID,
		ClientSecret:   o.clientSecret,
		TokenURL:       endpoint.TokenURL,
		Scopes:         options.Scopes,
		EndpointParams: options.EndpointParams,
		AuthStyle:      endpoint.AuthStyle,
	}

	tok, err := cc.Token(ctx)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:           tok,
		ProviderVersion: o.vsn,
		ProviderOptions: options.ProviderOptions,
	}, nil
}

func (o *oktaOperations) TokenExchange(ctx context.Context, t *Token, opts ...TokenExchangeOption) (*Token, error) {
	options := &TokenExchangeOptions{}
	options.ApplyOptions(opts)

	endpoint := o.endpointFactory(options.ProviderOptions)

	var cfg *oauth2.Config
	var exchangeOpts []oauth2.AuthCodeOption

	if o.usePrivateKey {
		assertion, err := o.generateJWT()
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT: %w", err)
		}

		cfg = &oauth2.Config{
			Endpoint: endpoint.Endpoint,
			ClientID: o.clientID,
		}

		exchangeOpts = append(exchangeOpts,
			oauth2.SetAuthURLParam(JWTAssertionTypeParam, JWTAssertionType),
			oauth2.SetAuthURLParam(JWTClientAssertionParam, assertion),
		)
	} else {
		if o.clientSecret == "" {
			return nil, errmark.MarkUser(ErrMissingClientSecret)
		}

		cfg = &oauth2.Config{
			Endpoint:     endpoint.Endpoint,
			ClientID:     o.clientID,
			ClientSecret: o.clientSecret,
		}
	}

	ctx = clientctx.WithUpdatedRequestBody(ctx, func(body []byte) ([]byte, error) {
		vs, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}

		if len(options.Audiences) > 0 {
			vs["audience"] = options.Audiences
		}
		if len(options.Resources) > 0 {
			vs["resource"] = options.Resources
		}

		return []byte(vs.Encode()), nil
	})

	exchangeOpts = append(exchangeOpts,
		oauth2.SetAuthURLParam("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
		oauth2.SetAuthURLParam("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"),
		oauth2.SetAuthURLParam("subject_token", t.AccessToken),
		oauth2.SetAuthURLParam("requested_token_type", "urn:ietf:params:oauth:token-type:access_token"),
	)

	if len(options.Scopes) > 0 {
		exchangeOpts = append(exchangeOpts, oauth2.SetAuthURLParam("scope", strings.Join(options.Scopes, " ")))
	}

	tok, err := cfg.Exchange(ctx, "", append(exchangeOpts, options.AuthCodeOptions...)...)
	if err != nil {
		return nil, err
	}

	return &Token{
		Token:           tok,
		ProviderVersion: o.vsn,
		ProviderOptions: options.ProviderOptions,
	}, nil
}

type okta struct {
	vsn             int
	endpointFactory EndpointFactoryFunc
	privateKey      *rsa.PrivateKey
	usePrivateKey   bool
}

func (o *okta) Version() int {
	return o.vsn
}

func (o *okta) Public(clientID string) PublicOperations {
	return o.Private(clientID, "")
}

func (o *okta) Private(clientID, clientSecret string) PrivateOperations {
	return &oktaOperations{
		vsn:             o.vsn,
		endpointFactory: o.endpointFactory,
		clientID:        clientID,
		clientSecret:    clientSecret,
		privateKey:      o.privateKey,
		usePrivateKey:   o.usePrivateKey,
	}
}

func OktaFactory(ctx context.Context, vsn int, opts map[string]string) (Provider, error) {
	vsn = selectVersion(vsn, OktaProviderV1)

	switch vsn {
	case OktaProviderV1:
	default:
		return nil, ErrNoProviderWithVersion
	}

	domain := opts[OptionDomain]
	if domain == "" {
		return nil, &OptionError{Option: OptionDomain, Cause: fmt.Errorf("domain is required")}
	}

	// Default to https unless specified otherwise (for testing)
	scheme := "https"
	if s := opts[OptionScheme]; s != "" {
		scheme = s
	}

	var privateKey *rsa.PrivateKey
	usePrivateKey := false

	if keyPEM := opts[OptionPrivateKey]; keyPEM != "" {
		block, _ := pem.Decode([]byte(keyPEM))
		if block == nil {
			return nil, &OptionError{Option: OptionPrivateKey, Cause: fmt.Errorf("failed to parse PEM block")}
		}

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, &OptionError{Option: OptionPrivateKey, Cause: fmt.Errorf("failed to parse private key: %w", err)}
		}

		privateKey = key
		usePrivateKey = true
	}

	p := &okta{
		vsn: vsn,
		endpointFactory: StaticEndpointFactory(Endpoint{
			Endpoint: oauth2.Endpoint{
				AuthURL:  fmt.Sprintf("%s://%s/oauth2/v1/authorize", scheme, domain),
				TokenURL: fmt.Sprintf("%s://%s/oauth2/v1/token", scheme, domain),
			},
		}),
		privateKey:    privateKey,
		usePrivateKey: usePrivateKey,
	}

	return p, nil
}
