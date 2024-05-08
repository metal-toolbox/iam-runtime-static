package server

import (
	"context"
	"os"
	"testing"

	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authentication"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/authorization"
	"github.com/metal-toolbox/iam-runtime/pkg/iam/runtime/identity"
	"golang.org/x/oauth2"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockedTokenSource struct {
	token string
	err   error
}

func (s mockedTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: s.token}, s.err
}

func TestServer(t *testing.T) {
	// Run everything in parallel
	t.Parallel()

	// Set up a server with a simple policy.
	subjectAlice := "alice"
	subjectBob := "bob"

	envVarAlice := "IAM_ALICE_TOKEN"
	envVarBob := "IAM_BOB_TOKEN"

	tokenAlice := "alic3!"
	tokenBob := "b0b"
	tokenDNE := "doesnotexist"

	actionGreet := "greet"

	resourceWorld := "resourc-world"

	// In this policy, Alice has the ability to greet the world, but Bob does not.
	authPolicy := policy{
		Subjects: []policySubject{
			{
				ID: subjectAlice,
				Tokens: []policyToken{
					{
						EnvVar: envVarAlice,
					},
				},
				Resources: []policyResource{
					{
						ID: resourceWorld,
						Actions: []string{
							actionGreet,
						},
					},
				},
			},
			{
				ID: subjectBob,
				Tokens: []policyToken{
					{
						EnvVar: envVarBob,
					},
				},
				Resources: []policyResource{},
			},
		},
	}

	// Set the environment variables for the test
	os.Setenv(envVarAlice, tokenAlice)
	os.Setenv(envVarBob, tokenBob)

	logger := zap.NewNop().Sugar()

	srv, err := newFromPolicy(authPolicy, logger, mockedTokenSource{token: "some access token"})

	require.NoError(t, err)

	t.Run("ValidateCredentialSuccess", func(t *testing.T) {
		t.Parallel()

		req := &authentication.ValidateCredentialRequest{
			Credential: tokenAlice,
		}
		resp, err := srv.ValidateCredential(context.Background(), req)

		require.NoError(t, err)
		require.Equal(t, authentication.ValidateCredentialResponse_RESULT_VALID, resp.Result)
		require.Equal(t, subjectAlice, resp.Subject.SubjectId)
	})

	t.Run("ValidateCredentialFail", func(t *testing.T) {
		t.Parallel()

		req := &authentication.ValidateCredentialRequest{
			Credential: tokenDNE,
		}
		resp, err := srv.ValidateCredential(context.Background(), req)

		require.NoError(t, err)
		require.Equal(t, authentication.ValidateCredentialResponse_RESULT_INVALID, resp.Result)
	})

	t.Run("CheckAccessSuccess", func(t *testing.T) {
		t.Parallel()

		req := &authorization.CheckAccessRequest{
			Credential: tokenAlice,
			Actions: []*authorization.AccessRequestAction{
				{
					ResourceId: resourceWorld,
					Action:     actionGreet,
				},
			},
		}
		resp, err := srv.CheckAccess(context.Background(), req)

		require.NoError(t, err)
		require.Equal(t, authorization.CheckAccessResponse_RESULT_ALLOWED, resp.Result)
	})

	t.Run("CheckAccessUnauthenticated", func(t *testing.T) {
		t.Parallel()

		req := &authorization.CheckAccessRequest{
			Credential: tokenDNE,
			Actions: []*authorization.AccessRequestAction{
				{
					ResourceId: resourceWorld,
					Action:     actionGreet,
				},
			},
		}

		_, err := srv.CheckAccess(context.Background(), req)

		errStatus, ok := status.FromError(err)

		require.Equal(t, true, ok)
		require.Equal(t, codes.InvalidArgument, errStatus.Code())
	})

	t.Run("CheckAccessUnauthorized", func(t *testing.T) {
		t.Parallel()

		req := &authorization.CheckAccessRequest{
			Credential: tokenBob,
			Actions: []*authorization.AccessRequestAction{
				{
					ResourceId: resourceWorld,
					Action:     actionGreet,
				},
			},
		}

		resp, err := srv.CheckAccess(context.Background(), req)

		require.NoError(t, err)
		require.Equal(t, authorization.CheckAccessResponse_RESULT_DENIED, resp.Result)
	})

	t.Run("GetAccessToken", func(t *testing.T) {
		t.Parallel()

		req := &identity.GetAccessTokenRequest{}

		resp, err := srv.GetAccessToken(context.Background(), req)

		require.NoError(t, err)
		require.Equal(t, "some access token", resp.Token)
	})
}
