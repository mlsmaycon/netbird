package selfhostedproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/status"
)

type mockDisconnector struct {
	disconnectedIDs []string
}

func (m *mockDisconnector) ForceDisconnect(proxyID string) {
	m.disconnectedIDs = append(m.disconnectedIDs, proxyID)
}

func authContext(accountID, userID string) context.Context {
	return nbcontext.SetUserAuthInContext(context.Background(), auth.UserAuth{
		AccountId: accountID,
		UserId:    userID,
	})
}

func TestListProxies_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accountID := "acc-123"
	now := time.Now()
	connAt := now.Add(-1 * time.Hour)

	proxyMgr := proxy.NewMockManager(ctrl)
	proxyMgr.EXPECT().GetAccountProxy(gomock.Any(), accountID).Return(&proxy.Proxy{
		ID:             "proxy-1",
		ClusterAddress: "byod.example.com",
		IPAddress:      "10.0.0.1",
		AccountID:      &accountID,
		Status:         proxy.StatusConnected,
		LastSeen:       now,
		ConnectedAt:    &connAt,
	}, nil)

	serviceMgr := rpservice.NewMockManager(ctrl)
	serviceMgr.EXPECT().GetAccountServices(gomock.Any(), accountID).Return([]*rpservice.Service{
		{ProxyCluster: "byod.example.com"},
		{ProxyCluster: "byod.example.com"},
		{ProxyCluster: "other.cluster.com"},
	}, nil)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), accountID, "user-1", modules.Services, operations.Read).Return(true, nil)

	h := &handler{
		proxyMgr:           proxyMgr,
		serviceMgr:         serviceMgr,
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("GET", "/reverse-proxies/self-hosted-proxies", nil)
	req = req.WithContext(authContext(accountID, "user-1"))
	w := httptest.NewRecorder()

	h.listProxies(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp []api.SelfHostedProxy
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.Len(t, resp, 1)
	assert.Equal(t, "proxy-1", resp[0].Id)
	assert.Equal(t, "byod.example.com", resp[0].ClusterAddress)
	assert.Equal(t, 2, resp[0].ServiceCount)
	assert.Equal(t, api.SelfHostedProxyStatus(proxy.StatusConnected), resp[0].Status)
}

func TestListProxies_NoProxy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	proxyMgr := proxy.NewMockManager(ctrl)
	proxyMgr.EXPECT().GetAccountProxy(gomock.Any(), "acc-123").Return(nil, status.Errorf(status.NotFound, "not found"))

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), "acc-123", "user-1", modules.Services, operations.Read).Return(true, nil)

	h := &handler{
		proxyMgr:           proxyMgr,
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("GET", "/reverse-proxies/self-hosted-proxies", nil)
	req = req.WithContext(authContext("acc-123", "user-1"))
	w := httptest.NewRecorder()

	h.listProxies(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp []api.SelfHostedProxy
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Empty(t, resp)
}

func TestListProxies_PermissionDenied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), "acc-123", "user-1", modules.Services, operations.Read).Return(false, nil)

	h := &handler{
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("GET", "/reverse-proxies/self-hosted-proxies", nil)
	req = req.WithContext(authContext("acc-123", "user-1"))
	w := httptest.NewRecorder()

	h.listProxies(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDeleteProxy_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accountID := "acc-123"
	disconnector := &mockDisconnector{}

	proxyMgr := proxy.NewMockManager(ctrl)
	proxyMgr.EXPECT().GetAccountProxy(gomock.Any(), accountID).Return(&proxy.Proxy{
		ID:        "proxy-1",
		AccountID: &accountID,
		Status:    proxy.StatusConnected,
	}, nil)
	proxyMgr.EXPECT().DeleteProxy(gomock.Any(), "proxy-1").Return(nil)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), accountID, "user-1", modules.Services, operations.Delete).Return(true, nil)

	h := &handler{
		proxyMgr:           proxyMgr,
		permissionsManager: permsMgr,
		disconnector:       disconnector,
	}

	req := httptest.NewRequest("DELETE", "/reverse-proxies/self-hosted-proxies/proxy-1", nil)
	req = req.WithContext(authContext(accountID, "user-1"))
	req = mux.SetURLVars(req, map[string]string{"proxyId": "proxy-1"})
	w := httptest.NewRecorder()

	h.deleteProxy(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, disconnector.disconnectedIDs, "proxy-1")
}

func TestDeleteProxy_WrongProxyID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	accountID := "acc-123"

	proxyMgr := proxy.NewMockManager(ctrl)
	proxyMgr.EXPECT().GetAccountProxy(gomock.Any(), accountID).Return(&proxy.Proxy{
		ID:        "proxy-1",
		AccountID: &accountID,
	}, nil)

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), accountID, "user-1", modules.Services, operations.Delete).Return(true, nil)

	h := &handler{
		proxyMgr:           proxyMgr,
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("DELETE", "/reverse-proxies/self-hosted-proxies/proxy-other", nil)
	req = req.WithContext(authContext(accountID, "user-1"))
	req = mux.SetURLVars(req, map[string]string{"proxyId": "proxy-other"})
	w := httptest.NewRecorder()

	h.deleteProxy(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteProxy_PermissionDenied(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	permsMgr := permissions.NewMockManager(ctrl)
	permsMgr.EXPECT().ValidateUserPermissions(gomock.Any(), "acc-123", "user-1", modules.Services, operations.Delete).Return(false, nil)

	h := &handler{
		permissionsManager: permsMgr,
	}

	req := httptest.NewRequest("DELETE", "/reverse-proxies/self-hosted-proxies/proxy-1", nil)
	req = req.WithContext(authContext("acc-123", "user-1"))
	req = mux.SetURLVars(req, map[string]string{"proxyId": "proxy-1"})
	w := httptest.NewRecorder()

	h.deleteProxy(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
