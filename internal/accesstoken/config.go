package accesstoken

import (
	"context"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/metal-toolbox/iam-runtime-static/internal/cmdtokensource"
	"github.com/metal-toolbox/iam-runtime-static/internal/jwt"
)

// Config defines the access token config.
type Config struct {
	Source struct {
		Command           cmdtokensource.Config
		ClientCredentials struct {
			Issuer       string
			ClientID     string
			ClientSecret string
		}
		Generate GeneratedConfig
	}
	Exchange ExchangeConfig
}

// ExchangeConfig defines the exchange config.
type ExchangeConfig struct {
	Issuer    string
	GrantType string
	TokenType string
}

// NewTokenSource creates a new token source from the access token config.
func NewTokenSource(ctx context.Context, cfg Config) (oauth2.TokenSource, error) {
	var (
		tokenSource oauth2.TokenSource
		err         error
	)

	switch {
	case cfg.Source.Command.Command != "":
		tokenSource = cmdtokensource.NewTokenSource(cfg.Source.Command)
	case cfg.Source.ClientCredentials.Issuer != "":
		tokenEndpoint, err := jwt.FetchIssuerTokenEndpoint(ctx, cfg.Source.ClientCredentials.Issuer)
		if err != nil {
			return nil, err
		}

		tokenSource = (&clientcredentials.Config{
			TokenURL:     tokenEndpoint,
			ClientID:     cfg.Source.ClientCredentials.ClientID,
			ClientSecret: cfg.Source.ClientCredentials.ClientSecret,
		}).TokenSource(ctx)
	default:
		tokenSource, err = newGeneratedTokenSource(cfg.Source.Generate)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Exchange.Issuer != "" {
		tokenSource, err = newExchangeTokenSource(ctx, cfg.Exchange, tokenSource)
		if err != nil {
			return nil, err
		}
	}

	return tokenSource, nil
}
