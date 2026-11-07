package handlers

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/subscription"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// addSubscriptionLinkEndpoints registers the subscription login routes. The
// link routes act only on the caller's own login, so they need no role gate;
// the manager checks that the caller's policies reach the provider. Listing
// every user's link state needs the providers read grant.
func (h *handler) addSubscriptionLinkEndpoints(router *mux.Router) {
	router.HandleFunc("/agent-network/providers/{providerId}/link", h.startProviderLink).Methods("POST", "OPTIONS")
	router.HandleFunc("/agent-network/providers/{providerId}/link", h.unlinkProvider).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/agent-network/providers/{providerId}/link/{flowId}", h.pollProviderLink).Methods("GET", "OPTIONS")
	router.HandleFunc("/agent-network/providers/{providerId}/links", h.listProviderLinks).Methods("GET", "OPTIONS")
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

func (h *handler) listProviderLinks(w http.ResponseWriter, r *http.Request) {
	userAuth, providerID, ok := linkRequestScope(w, r)
	if !ok {
		return
	}
	creds, err := h.manager.ListProviderLinks(r.Context(), userAuth.AccountId, userAuth.UserId, providerID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}
	out := make([]api.AgentNetworkProviderUserLink, 0, len(creds))
	for _, c := range creds {
		out = append(out, userLinkToAPI(c))
	}
	util.WriteJSONObject(r.Context(), w, out)
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

func userLinkToAPI(c *types.UserCredential) api.AgentNetworkProviderUserLink {
	out := api.AgentNetworkProviderUserLink{
		UserId:          c.UserID,
		Status:          api.AgentNetworkProviderUserLinkStatusLinked,
		LinkedAt:        c.CreatedAt,
		LastRefreshedAt: c.LastRefreshedAt,
	}
	if c.Status != types.UserCredentialActive {
		out.Status = api.AgentNetworkProviderUserLinkStatusNeedsRelink
	}
	if c.PlanType != "" {
		plan := c.PlanType
		out.PlanType = &plan
	}
	return out
}

func subscriptionLinkToAPI(state *types.SubscriptionLinkState) *api.AgentNetworkSubscriptionLink {
	if state == nil {
		return nil
	}
	out := &api.AgentNetworkSubscriptionLink{
		Status:   api.AgentNetworkSubscriptionLinkStatus(state.Status),
		LinkedAt: state.LinkedAt,
	}
	if state.PlanType != "" {
		plan := state.PlanType
		out.PlanType = &plan
	}
	return out
}
