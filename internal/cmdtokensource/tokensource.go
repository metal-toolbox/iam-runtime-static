// Package cmdtokensource executes a command to retrieve a token.
package cmdtokensource

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// TokenSource implemenets oauth2.TokenSource returning the token from the provided command.
// Loaded tokens are reused.
type TokenSource struct {
	mu    sync.Mutex
	cfg   Config
	token *oauth2.Token
}

// Token returns the latest token from the configured command.
// Unless Config.NoReuseToken is true, tokens are reused while they're still valid.
func (s *TokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.cfg.NoReuseToken && s.token != nil && s.token.Valid() {
		return s.token, nil
	}

	tokenb, err := runShellCommand(s.cfg)
	if err != nil {
		return nil, err
	}

	newToken := string(tokenb)

	// Token signature is not validated here because we only need the expiry time from the claims.
	token, _, err := jwt.NewParser().ParseUnverified(newToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("error parsing jwt: %w", err)
	}

	expiry, err := token.Claims.GetExpirationTime()
	if err != nil {
		return nil, fmt.Errorf("error getting expiration time from jwt: %w", err)
	}

	var expiryTime time.Time

	if expiry != nil {
		expiryTime = expiry.Time
	}

	s.token = &oauth2.Token{
		AccessToken: newToken,
		TokenType:   "Bearer",
		Expiry:      expiryTime,
	}

	return s.token, nil
}

func runShellCommand(cfg Config) ([]byte, error) {
	var (
		shellCmd  string
		shellArgs []string
	)

	shellParts := strings.Split(cfg.Shell, " ")
	if len(shellParts) != 0 {
		if shellParts[0] != "" {
			if !strings.HasPrefix(shellParts[0], "-") {
				shellCmd = shellParts[0]

				if len(shellParts) > 1 {
					shellArgs = shellParts[1:]
				}
			} else {
				shellArgs = shellParts
			}
		}
	}

	if shellCmd == "" {
		shellCmd = os.Getenv("SHELL")
	}

	if len(shellArgs) == 0 {
		shellArgs = append(shellArgs, "-ec")
	}

	if shellCmd == "" {
		shellCmd = "/usr/bin/env"

		shellArgs = append([]string{"sh"}, shellArgs...)
	}

	shellArgs = append(shellArgs, cfg.Command)

	cmd := exec.Command(shellCmd, shellArgs...)

	out, err := cmd.Output()
	if err != nil {
		var stderr string

		if eErr, ok := err.(*exec.ExitError); ok {
			stderr = ": stderr: " + string(eErr.Stderr)
		}

		return nil, fmt.Errorf("failed to execute command %s %q: %w%s", shellCmd, shellArgs, err, stderr)
	}

	return out, nil
}

// NewTokenSource creates a new command token source.
func NewTokenSource(cfg Config) oauth2.TokenSource {
	return &TokenSource{
		cfg: cfg,
	}
}
