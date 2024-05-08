package cmdtokensource

import (
	"errors"
)

// ErrCommandRequired is returned when the Config.Command is not configured.
var ErrCommandRequired = errors.New("file token source: Command required")

// Config describes the configuration for the token source.
type Config struct {
	// Shell specifies the shell to execute the command with.
	// Default `$SHELL -ec`
	Shell string

	// Command is the command executed to return a token.
	Command string

	// NoReuseToken if enabled disables reusing of tokens while they're still valid.
	// Each request to [TokenSource.Token] will result in the latest token being loaded.
	NoReuseToken bool
}

// WithCommand returns a new Config with the provided command defined.
func (c Config) WithCommand(cmd string) Config {
	c.Command = cmd

	return c
}

// ReuseToken returns a new Config with NoReuseToken defined.
func (c Config) ReuseToken(reuse bool) Config {
	c.NoReuseToken = !reuse

	return c
}

// Configured returns true when Command is defined.
func (c Config) Configured() bool {
	return c.Command != ""
}

// Validate ensures the config has been configured properly.
func (c Config) Validate() error {
	if c.Command == "" {
		return ErrCommandRequired
	}

	return nil
}

// ToTokenSource initializes a new [TokenSource] with the defined config.
func (c Config) ToTokenSource() (*TokenSource, error) {
	if c.Command == "" {
		return nil, ErrCommandRequired
	}

	tokenSource := &TokenSource{
		cfg: c,
	}

	if _, err := tokenSource.Token(); err != nil {
		return nil, err
	}

	return tokenSource, nil
}
