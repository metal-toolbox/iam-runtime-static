package jwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

var (
	tokenEndpointClient = &http.Client{
		Timeout:   5 * time.Second, // nolint:gomnd // clear and unexported
		Transport: http.DefaultTransport,
	}

	// ErrTokenEndpointMissing is returned when the issuers .well-known/openid-configuration is missing the token_endpoint key.
	ErrTokenEndpointMissing = errors.New("token endpoint missing from issuer well-known openid-configuration")
)

type jwksTokenEndpoint struct {
	TokenEndpoint string `json:"token_endpoint"`
}

// FetchIssuerTokenEndpoint returns the token endpoint for the provided issuer.
func FetchIssuerTokenEndpoint(ctx context.Context, issuer string) (string, error) {
	uri, err := url.JoinPath(issuer, ".well-known", "openid-configuration")
	if err != nil {
		return "", fmt.Errorf("invalid issuer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return "", err
	}

	res, err := tokenEndpointClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close() //nolint:errcheck // no need to check

	var jwks jwksTokenEndpoint
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		return "", err
	}

	return jwks.TokenEndpoint, nil
}
