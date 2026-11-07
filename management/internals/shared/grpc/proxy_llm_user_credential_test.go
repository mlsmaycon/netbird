package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/subscription"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type fakeCredentialService struct {
	access *subscription.Access
	err    error
	calls  int
}

func (f *fakeCredentialService) GetUserCredentialAccess(_ context.Context, _, _, _ string) (*subscription.Access, error) {
	f.calls++
	return f.access, f.err
}

func TestGetLLMUserCredential_ReturnsHeaders(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	fake := &fakeCredentialService{access: &subscription.Access{
		Headers:   []subscription.Header{{Name: "Authorization", Value: "Bearer at"}, {Name: "chatgpt-account-id", Value: "acct"}},
		ExpiresAt: expiry,
	}}
	s := &ProxyServiceServer{}
	s.SetAgentNetworkCredentialService(fake)

	resp, err := s.GetLLMUserCredential(context.Background(), &proto.GetLLMUserCredentialRequest{AccountId: "acc", UserId: "u", ProviderId: "p"})
	require.NoError(t, err)
	assert.Equal(t, proto.GetLLMUserCredentialResponse_OK, resp.GetStatus())
	require.Len(t, resp.GetHeaders(), 2)
	assert.Equal(t, "chatgpt-account-id", resp.GetHeaders()[1].GetName())
	assert.True(t, expiry.Equal(resp.GetExpiresAt().AsTime()), "expiry should round-trip")
}

func TestGetLLMUserCredential_MapsFailuresToStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want proto.GetLLMUserCredentialResponse_Status
	}{
		{"not linked", subscription.ErrNotLinked, proto.GetLLMUserCredentialResponse_NOT_LINKED},
		{"provider not linkable", agentnetwork.ErrProviderNotLinkable, proto.GetLLMUserCredentialResponse_NOT_LINKED},
		{"needs relink", subscription.ErrRelinkRequired, proto.GetLLMUserCredentialResponse_NEEDS_RELINK},
		{"anything else", errors.New("vendor down"), proto.GetLLMUserCredentialResponse_UNAVAILABLE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &ProxyServiceServer{}
			s.SetAgentNetworkCredentialService(&fakeCredentialService{err: tc.err})
			resp, err := s.GetLLMUserCredential(context.Background(), &proto.GetLLMUserCredentialRequest{AccountId: "acc", UserId: "u", ProviderId: "p"})
			require.NoError(t, err)
			assert.Equal(t, tc.want, resp.GetStatus())
			assert.Empty(t, resp.GetHeaders(), "a failure must never carry headers")
		})
	}
}

func TestGetLLMUserCredential_EnforcesAccountScope(t *testing.T) {
	fake := &fakeCredentialService{}
	s := &ProxyServiceServer{}
	s.SetAgentNetworkCredentialService(fake)
	scoped := "acc-1"
	ctx := context.WithValue(context.Background(), ProxyTokenContextKey, &types.ProxyAccessToken{AccountID: &scoped})

	_, err := s.GetLLMUserCredential(ctx, &proto.GetLLMUserCredentialRequest{AccountId: "acc-2", UserId: "u", ProviderId: "p"})
	assert.Equal(t, codes.PermissionDenied, grpcstatus.Code(err), "an account-scoped proxy must not fetch another account's logins")
	assert.Zero(t, fake.calls)
}

func TestGetLLMUserCredential_Unimplemented(t *testing.T) {
	s := &ProxyServiceServer{}
	_, err := s.GetLLMUserCredential(context.Background(), &proto.GetLLMUserCredentialRequest{AccountId: "acc", ProviderId: "p"})
	assert.Equal(t, codes.Unimplemented, grpcstatus.Code(err))
}
