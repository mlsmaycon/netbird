package handlers

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/subscription"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// addSubscriptionLinkEndpoints registers the routes that link a subscription
// login to a provider. The manager requires permission to update providers.
func (h *handler) addSubscriptionLinkEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/providers/{providerId}/link", h.startProviderLink).Methods("POST", "OPTIONS")
	router.HandleFunc("/agent-network/providers/{providerId}/link", h.unlinkProvider).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/agent-network/providers/{providerId}/link/{flowId}", h.pollProviderLink).Methods("GET", "OPTIONS")
}

func (h *handler) startProviderLink(w http.ResponseWriter, r *http.Request) {
	userAuth, providerID, ok := linkRequestScope(w, r)
	if !ok {
		return
	}
	flow, err := h.manager.StartProviderLink(r.Context(), userAuth.AccountId, userAuth.UserId, providerID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, linkFlowToAPI(flow))
}

func (h *handler) pollProviderLink(w http.ResponseWriter, r *http.Request) {
	userAuth, providerID, ok := linkRequestScope(w, r)
	if !ok {
		return
	}
	flowID := mux.Vars(r)["flowId"]
	if flowID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "flow ID is required"), w)
		return
	}
	flow, err := h.manager.PollProviderLink(r.Context(), userAuth.AccountId, userAuth.UserId, providerID, flowID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, linkFlowToAPI(flow))
}

func (h *handler) unlinkProvider(w http.ResponseWriter, r *http.Request) {
	userAuth, providerID, ok := linkRequestScope(w, r)
	if !ok {
		return
	}
	if err := h.manager.UnlinkProvider(r.Context(), userAuth.AccountId, userAuth.UserId, providerID); err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

func linkRequestScope(w http.ResponseWriter, r *http.Request) (*auth.UserAuth, string, bool) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return nil, "", false
	}
	providerID := mux.Vars(r)["providerId"]
	if providerID == "" {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "provider ID is required"), w)
		return nil, "", false
	}
	return &userAuth, providerID, true
}

func linkFlowToAPI(flow *subscription.Flow) api.AgentNetworkProviderLinkFlow {
	return api.AgentNetworkProviderLinkFlow{
		Id:              flow.ID,
		Status:          api.AgentNetworkProviderLinkFlowStatus(flow.Status),
		UserCode:        flow.UserCode,
		VerificationUri: flow.VerificationURI,
		ExpiresAt:       flow.ExpiresAt,
		IntervalSeconds: int(flow.Interval.Seconds()),
	}
}
