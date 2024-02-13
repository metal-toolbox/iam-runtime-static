package server

import (
	"io"

	"gopkg.in/yaml.v3"
)

type policyToken struct {
	EnvVar string `yaml:"envVar"`
}

type policyResource struct {
	ID      string
	Actions []string
}

type policySubject struct {
	ID        string
	Tokens    []policyToken
	Resources []policyResource
}

type policy struct {
	Subjects []policySubject
}

func readPolicy(r io.Reader) (policy, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return policy{}, err
	}

	var out policy
	if err := yaml.Unmarshal(b, &out); err != nil {
		return policy{}, err
	}

	return out, nil
}
