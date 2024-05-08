package accesstoken

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	gojwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

const keySize = 2048

// GeneratedConfig defines the configuration for a generated token source.
type GeneratedConfig struct {
	Issuer     string
	Subject    string
	Expiration time.Duration
}

type generatedTokenSource struct {
	signer jose.Signer
	cfg    GeneratedConfig
}

func (s generatedTokenSource) Token() (*oauth2.Token, error) {
	var tokExpiry *jwt.NumericDate

	if s.cfg.Expiration != 0 {
		tokExpiry = jwt.NewNumericDate(time.Now().Add(s.cfg.Expiration))
	}

	claims := jwt.Claims{
		Issuer:    s.cfg.Issuer,
		Subject:   s.cfg.Subject,
		Expiry:    tokExpiry,
		NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Second)),
	}

	token, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		return nil, err
	}

	jwt, _, err := gojwt.NewParser().ParseUnverified(token, gojwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	expiry, err := jwt.Claims.GetExpirationTime()
	if err != nil {
		return nil, err
	}

	var expiryTime time.Time

	if expiry != nil {
		expiryTime = expiry.Time
	}

	return &oauth2.Token{
		AccessToken: token,
		TokenType:   "Bearer",
		Expiry:      expiryTime,
	}, nil
}

func newGeneratedTokenSource(cfg GeneratedConfig) (oauth2.TokenSource, error) {
	if cfg.Subject == "" {
		cfg.Subject = "some subject"
	}

	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       key,
		}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "generated"),
	)

	if err != nil {
		return nil, err
	}

	tokenSource := generatedTokenSource{
		signer: signer,
		cfg:    cfg,
	}

	return oauth2.ReuseTokenSource(nil, tokenSource), nil
}
