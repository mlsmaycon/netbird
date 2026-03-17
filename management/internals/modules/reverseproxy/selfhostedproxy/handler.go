package selfhostedproxy

import (
	"net/http"

	"github.com/gorilla/mux"

	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ProxyDisconnector can force-disconnect a connected proxy's gRPC stream.
type ProxyDisconnector interface {
	ForceDisconnect(proxyID string)
}

type handler struct {
	proxyMgr           proxy.Manager
	serviceMgr         rpservice.Manager
	permissionsManager permissions.Manager
	disconnector       ProxyDisconnector
}

func RegisterEndpoints(proxyMgr proxy.Manager, serviceMgr rpservice.Manager, permissionsManager permissions.Manager, disconnector ProxyDisconnector, router *mux.Router) {
	h := &handler{
		proxyMgr:           proxyMgr,
		serviceMgr:         serviceMgr,
		permissionsManager: permissionsManager,
		disconnector:       disconnector,
	}
	router.HandleFunc("/reverse-proxies/self-hosted-proxies", h.listProxies).Methods("GET", "OPTIONS")
	router.HandleFunc("/reverse-proxies/self-hosted-proxies/{proxyId}", h.deleteProxy).Methods("DELETE", "OPTIONS")
}

func (h *handler) listProxies(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ok, err := h.permissionsManager.ValidateUserPermissions(r.Context(), userAuth.AccountId, userAuth.UserId, modules.Services, operations.Read)
	if err != nil {
		util.WriteErrorResponse("failed to validate permissions", http.StatusInternalServerError, w)
		return
	}
	if !ok {
		util.WriteErrorResponse("permission denied", http.StatusForbidden, w)
		return
	}

	p, err := h.proxyMgr.GetAccountProxy(r.Context(), userAuth.AccountId)
	if err != nil {
		if isNotFound(err) {
			util.WriteJSONObject(r.Context(), w, []api.SelfHostedProxy{})
			return
		}
		util.WriteErrorResponse("failed to get proxy", http.StatusInternalServerError, w)
		return
	}

	serviceCount := 0
	services, err := h.serviceMgr.GetAccountServices(r.Context(), userAuth.AccountId)
	if err == nil {
		for _, svc := range services {
			if svc.ProxyCluster == p.ClusterAddress {
				serviceCount++
			}
		}
	}

	resp := []api.SelfHostedProxy{toSelfHostedProxyResponse(p, serviceCount)}
	util.WriteJSONObject(r.Context(), w, resp)
}

func (h *handler) deleteProxy(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	ok, err := h.permissionsManager.ValidateUserPermissions(r.Context(), userAuth.AccountId, userAuth.UserId, modules.Services, operations.Delete)
	if err != nil {
		util.WriteErrorResponse("failed to validate permissions", http.StatusInternalServerError, w)
		return
	}
	if !ok {
		util.WriteErrorResponse("permission denied", http.StatusForbidden, w)
		return
	}

	proxyID := mux.Vars(r)["proxyId"]
	if proxyID == "" {
		util.WriteErrorResponse("proxy ID is required", http.StatusBadRequest, w)
		return
	}

	p, err := h.proxyMgr.GetAccountProxy(r.Context(), userAuth.AccountId)
	if err != nil {
		util.WriteErrorResponse("proxy not found", http.StatusNotFound, w)
		return
	}

	if p.ID != proxyID {
		util.WriteErrorResponse("proxy not found", http.StatusNotFound, w)
		return
	}

	if h.disconnector != nil {
		h.disconnector.ForceDisconnect(proxyID)
	}

	if err := h.proxyMgr.DeleteProxy(r.Context(), proxyID); err != nil {
		util.WriteErrorResponse("failed to delete proxy", http.StatusInternalServerError, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func isNotFound(err error) bool {
	e, ok := status.FromError(err)
	return ok && e.Type() == status.NotFound
}

func toSelfHostedProxyResponse(p *proxy.Proxy, serviceCount int) api.SelfHostedProxy {
	st := api.SelfHostedProxyStatus(p.Status)
	resp := api.SelfHostedProxy{
		Id:             p.ID,
		ClusterAddress: p.ClusterAddress,
		Status:         st,
		LastSeen:       p.LastSeen,
		ServiceCount:   serviceCount,
	}
	if p.IPAddress != "" {
		resp.IpAddress = &p.IPAddress
	}
	if p.ConnectedAt != nil {
		resp.ConnectedAt = p.ConnectedAt
	}
	return resp
}
