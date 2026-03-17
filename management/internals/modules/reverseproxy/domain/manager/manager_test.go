package manager

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockProxyManager struct {
	getActiveClusterAddressesFunc          func(ctx context.Context) ([]string, error)
	getActiveClusterAddressesForAccountFunc func(ctx context.Context, accountID string) ([]string, error)
}

func (m *mockProxyManager) GetActiveClusterAddresses(ctx context.Context) ([]string, error) {
	if m.getActiveClusterAddressesFunc != nil {
		return m.getActiveClusterAddressesFunc(ctx)
	}
	return nil, nil
}

func (m *mockProxyManager) GetActiveClusterAddressesForAccount(ctx context.Context, accountID string) ([]string, error) {
	if m.getActiveClusterAddressesForAccountFunc != nil {
		return m.getActiveClusterAddressesForAccountFunc(ctx, accountID)
	}
	return nil, nil
}

func TestGetClusterAllowList_BYODProxy(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, accID string) ([]string, error) {
			assert.Equal(t, "acc-123", accID)
			return []string{"byod.example.com"}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			t.Fatal("should not call GetActiveClusterAddresses when BYOD addresses exist")
			return nil, nil
		},
	}

	mgr := Manager{proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"byod.example.com"}, result)
}

func TestGetClusterAllowList_NoBYOD_FallbackToShared(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return nil, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io", "us.proxy.netbird.io"}, nil
		},
	}

	mgr := Manager{proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"eu.proxy.netbird.io", "us.proxy.netbird.io"}, result)
}

func TestGetClusterAllowList_BYODError_FallbackToShared(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return nil, errors.New("db error")
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io"}, nil
		},
	}

	mgr := Manager{proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"eu.proxy.netbird.io"}, result)
}

func TestGetClusterAllowList_BYODEmptySlice_FallbackToShared(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return []string{}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io"}, nil
		},
	}

	mgr := Manager{proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"eu.proxy.netbird.io"}, result)
}

func TestExtractClusterFromFreeDomain(t *testing.T) {
	clusters := []string{"eu.proxy.netbird.io", "us.proxy.netbird.io"}

	tests := []struct {
		name        string
		domain      string
		wantCluster string
		wantOK      bool
	}{
		{
			name:        "matches EU cluster",
			domain:      "myapp.abc123.eu.proxy.netbird.io",
			wantCluster: "eu.proxy.netbird.io",
			wantOK:      true,
		},
		{
			name:        "matches US cluster",
			domain:      "myapp.xyz789.us.proxy.netbird.io",
			wantCluster: "us.proxy.netbird.io",
			wantOK:      true,
		},
		{
			name:   "no match - custom domain",
			domain: "app.example.com",
			wantOK: false,
		},
		{
			name:   "no match - partial cluster name",
			domain: "proxy.netbird.io",
			wantOK: false,
		},
		{
			name:   "exact cluster name - no prefix",
			domain: "eu.proxy.netbird.io",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cluster, ok := ExtractClusterFromFreeDomain(tt.domain, clusters)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantCluster, cluster)
			}
		})
	}
}
