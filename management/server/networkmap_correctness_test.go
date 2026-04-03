package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// TestNetworkMapCorrectness_LegacyVsCompacted verifies that legacy and compacted
// network map calculation produce identical results across various account configurations.
// This test serves as the safety net for any optimization work.
func TestNetworkMapCorrectness_LegacyVsCompacted(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	testCases := []struct {
		name    string
		account *types.Account
		// peerIDs to test - if empty, tests ALL peers in the account
		peerIDs []string
		// excludeFromValidation - peer IDs to exclude from validated peers map
		excludeFromValidation []string
	}{
		{
			name:    "simple_two_groups_bidirectional",
			account: buildSimpleTwoGroupAccount(),
		},
		{
			name:    "all_peers_single_policy",
			account: buildAllPeersSinglePolicyAccount(),
		},
		{
			name:    "multi_policy_with_port_rules",
			account: buildMultiPolicyWithPortRules(),
		},
		{
			name:    "with_network_resources_and_routers",
			account: buildAccountWithNetworkResources(),
		},
		{
			name:    "with_expired_peers",
			account: buildAccountWithExpiredPeers(),
		},
		{
			name:    "with_posture_checks",
			account: buildAccountWithPostureChecks(),
		},
		{
			name:    "with_routes_and_access_control",
			account: buildAccountWithRoutes(),
		},
		{
			name:    "with_dns_and_nameservers",
			account: buildAccountWithDNS(),
		},
		{
			name:    "overlapping_groups",
			account: buildAccountWithOverlappingGroups(),
		},
		{
			name:    "disabled_policies_and_rules",
			account: buildAccountWithDisabledPolicies(),
		},
		{
			name:    "drop_action_policies",
			account: buildAccountWithDropPolicies(),
		},
		{
			name:    "peer_not_in_any_policy",
			account: buildAccountWithIsolatedPeer(),
			peerIDs: []string{"isolated-peer"},
		},
		{
			name:    "large_scale_500_peers_50_groups",
			account: buildLargeAccount(t, 500, 50),
		},
		{
			name:    "unidirectional_policies",
			account: buildAccountWithUnidirectionalPolicies(),
		},
		{
			name:    "ssh_policies",
			account: buildAccountWithSSHPolicy(),
		},
		{
			name:    "multiple_network_resources_and_routers",
			account: buildAccountWithMultipleNetworkResources(),
		},
		{
			name:    "ha_routes_same_network",
			account: buildAccountWithHARoutes(),
		},
		{
			name:    "disabled_routes_and_resources",
			account: buildAccountWithDisabledRoutesAndResources(),
		},
		{
			name:    "multiple_nameserver_groups",
			account: buildAccountWithMultipleNameservers(),
		},
		{
			name:    "dns_disabled_management_groups",
			account: buildAccountWithDNSDisabledManagement(),
		},
		{
			name:    "peer_as_routing_peer",
			account: buildAccountWithRoutingPeerPerspective(),
			peerIDs: []string{"router-peer", "peer-0", "peer-5"},
		},
		{
			name:    "peer_resource_policy",
			account: buildAccountWithPeerResourcePolicy(),
		},
		{
			name:                  "validated_peers_exclusion",
			account:               buildAccountWithValidatedPeersExclusion(),
			excludeFromValidation: []string{"peer-3", "peer-7"},
		},
		{
			name:    "multiple_posture_checks_on_policies",
			account: buildAccountWithMultiplePostureChecks(),
		},
		{
			name:    "services_with_proxy_policies",
			account: buildAccountWithServiceProxyPolicies(),
		},
		{
			name:    "mixed_protocol_policies",
			account: buildAccountWithMixedProtocols(),
		},
		{
			name:    "port_ranges_policy",
			account: buildAccountWithPortRanges(),
		},
		{
			name:    "large_group_count_many_policies",
			account: buildAccountWithManyGroupsAndPolicies(),
		},
		{
			name:    "network_resource_with_multiple_source_groups",
			account: buildAccountWithNRMultipleSourceGroups(),
		},
		{
			name:    "account_settings_expiration_variants",
			account: buildAccountWithExpirationVariants(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			account := tc.account
			ctx := context.Background()

			excludeSet := make(map[string]struct{})
			for _, id := range tc.excludeFromValidation {
				excludeSet[id] = struct{}{}
			}
			validatedPeersMap := make(map[string]struct{}, len(account.Peers))
			for peerID := range account.Peers {
				if _, excluded := excludeSet[peerID]; !excluded {
					validatedPeersMap[peerID] = struct{}{}
				}
			}

			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()

			peersToTest := tc.peerIDs
			if len(peersToTest) == 0 {
				for peerID := range account.Peers {
					peersToTest = append(peersToTest, peerID)
				}
			}

			for _, peerID := range peersToTest {
				legacyMap := account.GetPeerNetworkMap(
					ctx, peerID, nbdns.CustomZone{}, nil,
					validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
				)

				compactedMap := account.GetPeerNetworkMapFromComponents(
					ctx, peerID, nbdns.CustomZone{}, nil,
					validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
				)

				assertNetworkMapsEqual(t, peerID, legacyMap, compactedMap)
			}
		})
	}
}

// TestNetworkMapCorrectness_FieldValues validates specific field values in
// the network map to ensure critical data is correctly populated.
func TestNetworkMapCorrectness_FieldValues(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	account := buildAccountWithRoutes()
	ctx := context.Background()

	validatedPeersMap := make(map[string]struct{}, len(account.Peers))
	for peerID := range account.Peers {
		validatedPeersMap[peerID] = struct{}{}
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	for _, peerID := range []string{"peer-0", "peer-5", "peer-9"} {
		nm := account.GetPeerNetworkMap(
			ctx, peerID, nbdns.CustomZone{}, nil,
			validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
		)
		nmCompacted := account.GetPeerNetworkMapFromComponents(
			ctx, peerID, nbdns.CustomZone{}, nil,
			validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
		)

		t.Run(peerID+"/network_set", func(t *testing.T) {
			require.NotNil(t, nm.Network, "legacy NetworkMap.Network should not be nil")
			require.NotNil(t, nmCompacted.Network, "compacted NetworkMap.Network should not be nil")
			assert.Equal(t, nm.Network.Serial, nmCompacted.Network.Serial)
		})

		t.Run(peerID+"/peers_not_contain_self", func(t *testing.T) {
			for _, p := range nm.Peers {
				assert.NotEqual(t, peerID, p.ID, "legacy: peer list should not contain self")
			}
			for _, p := range nmCompacted.Peers {
				assert.NotEqual(t, peerID, p.ID, "compacted: peer list should not contain self")
			}
		})

		t.Run(peerID+"/peer_count_match", func(t *testing.T) {
			assert.Equal(t, len(nm.Peers), len(nmCompacted.Peers),
				"peer count: legacy=%d compacted=%d", len(nm.Peers), len(nmCompacted.Peers))
		})

		t.Run(peerID+"/firewall_rules_match", func(t *testing.T) {
			assert.Equal(t, len(nm.FirewallRules), len(nmCompacted.FirewallRules),
				"firewall rules: legacy=%d compacted=%d", len(nm.FirewallRules), len(nmCompacted.FirewallRules))
		})

		t.Run(peerID+"/routes_match", func(t *testing.T) {
			assert.Equal(t, len(nm.Routes), len(nmCompacted.Routes),
				"routes: legacy=%d compacted=%d", len(nm.Routes), len(nmCompacted.Routes))
		})
	}
}

// TestNetworkMapCorrectness_ExpiredPeersIsolation verifies that expired peers
// appear in OfflinePeers, not in active Peers.
func TestNetworkMapCorrectness_ExpiredPeersIsolation(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	account := buildAccountWithExpiredPeers()
	ctx := context.Background()

	validatedPeersMap := make(map[string]struct{}, len(account.Peers))
	for peerID := range account.Peers {
		validatedPeersMap[peerID] = struct{}{}
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	// Test from a non-expired peer's perspective
	nm := account.GetPeerNetworkMap(
		ctx, "peer-0", nbdns.CustomZone{}, nil,
		validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
	)

	nmCompacted := account.GetPeerNetworkMapFromComponents(
		ctx, "peer-0", nbdns.CustomZone{}, nil,
		validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
	)

	// Verify expired peers are in OfflinePeers for both modes
	for _, label := range []string{"legacy", "compacted"} {
		var testNm *types.NetworkMap
		if label == "legacy" {
			testNm = nm
		} else {
			testNm = nmCompacted
		}

		expiredFound := false
		for _, p := range testNm.OfflinePeers {
			if p.ID == "expired-peer" {
				expiredFound = true
			}
		}

		activeExpiredFound := false
		for _, p := range testNm.Peers {
			if p.ID == "expired-peer" {
				activeExpiredFound = true
			}
		}

		assert.True(t, expiredFound, "%s: expired peer should be in OfflinePeers", label)
		assert.False(t, activeExpiredFound, "%s: expired peer should NOT be in active Peers", label)
	}

	// Compare the two
	assertNetworkMapsEqual(t, "peer-0", nm, nmCompacted)
}

// TestNetworkMapCorrectness_JSONSnapshot takes a JSON snapshot of network maps
// from both modes and compares them byte-for-byte after normalization.
// This catches any subtle differences in field values, not just counts.
func TestNetworkMapCorrectness_JSONSnapshot(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	account := buildAccountWithRoutes()
	ctx := context.Background()

	validatedPeersMap := make(map[string]struct{}, len(account.Peers))
	for peerID := range account.Peers {
		validatedPeersMap[peerID] = struct{}{}
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	for _, peerID := range []string{"peer-0", "peer-5"} {
		t.Run(peerID, func(t *testing.T) {
			legacy := account.GetPeerNetworkMap(
				ctx, peerID, nbdns.CustomZone{}, nil,
				validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
			)
			compacted := account.GetPeerNetworkMapFromComponents(
				ctx, peerID, nbdns.CustomZone{}, nil,
				validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
			)

			normalizeNetworkMap(legacy)
			normalizeNetworkMap(compacted)

			legacyJSON, err := json.Marshal(legacy)
			require.NoError(t, err)
			compactedJSON, err := json.Marshal(compacted)
			require.NoError(t, err)

			assert.JSONEq(t, string(legacyJSON), string(compactedJSON),
				"JSON snapshots differ for peer %s", peerID)
		})
	}
}

// TestNetworkMapCorrectness_AllPeersConsistency verifies that when computing
// maps for ALL peers in an account, every peer gets consistent results from
// both legacy and compacted modes.
func TestNetworkMapCorrectness_AllPeersConsistency(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	account := buildAccountWithOverlappingGroups()
	ctx := context.Background()

	validatedPeersMap := make(map[string]struct{}, len(account.Peers))
	for peerID := range account.Peers {
		validatedPeersMap[peerID] = struct{}{}
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()

	mismatches := 0
	for peerID := range account.Peers {
		legacy := account.GetPeerNetworkMap(
			ctx, peerID, nbdns.CustomZone{}, nil,
			validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
		)
		compacted := account.GetPeerNetworkMapFromComponents(
			ctx, peerID, nbdns.CustomZone{}, nil,
			validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs,
		)

		if len(legacy.Peers) != len(compacted.Peers) ||
			len(legacy.FirewallRules) != len(compacted.FirewallRules) ||
			len(legacy.Routes) != len(compacted.Routes) ||
			len(legacy.RoutesFirewallRules) != len(compacted.RoutesFirewallRules) {
			mismatches++
			t.Errorf("Mismatch for peer %s: peers=%d/%d rules=%d/%d routes=%d/%d routeRules=%d/%d",
				peerID,
				len(legacy.Peers), len(compacted.Peers),
				len(legacy.FirewallRules), len(compacted.FirewallRules),
				len(legacy.Routes), len(compacted.Routes),
				len(legacy.RoutesFirewallRules), len(compacted.RoutesFirewallRules),
			)
		}
	}

	t.Logf("Checked %d peers, %d mismatches", len(account.Peers), mismatches)
}

// --- Helper: assert two network maps are equal ---

func assertNetworkMapsEqual(t *testing.T, peerID string, legacy, compacted *types.NetworkMap) {
	t.Helper()

	require.NotNil(t, legacy, "peer %s: legacy map is nil", peerID)
	require.NotNil(t, compacted, "peer %s: compacted map is nil", peerID)

	// Network
	assert.Equal(t, legacy.Network.Serial, compacted.Network.Serial,
		"peer %s: Network.Serial", peerID)

	// Peers
	legacyPeerIDs := peerIDSet(legacy.Peers)
	compactedPeerIDs := peerIDSet(compacted.Peers)
	assert.Equal(t, legacyPeerIDs, compactedPeerIDs,
		"peer %s: Peers set mismatch", peerID)

	// OfflinePeers
	legacyOffline := peerIDSet(legacy.OfflinePeers)
	compactedOffline := peerIDSet(compacted.OfflinePeers)
	assert.Equal(t, legacyOffline, compactedOffline,
		"peer %s: OfflinePeers set mismatch", peerID)

	// Firewall rules count
	assert.Equal(t, len(legacy.FirewallRules), len(compacted.FirewallRules),
		"peer %s: FirewallRules count", peerID)

	// Firewall rules content
	if len(legacy.FirewallRules) == len(compacted.FirewallRules) {
		normalizeFirewallRules(legacy.FirewallRules)
		normalizeFirewallRules(compacted.FirewallRules)
		for i := range legacy.FirewallRules {
			assert.Equal(t, legacy.FirewallRules[i].PeerIP, compacted.FirewallRules[i].PeerIP,
				"peer %s: rule[%d].PeerIP", peerID, i)
			assert.Equal(t, legacy.FirewallRules[i].Direction, compacted.FirewallRules[i].Direction,
				"peer %s: rule[%d].Direction", peerID, i)
			assert.Equal(t, legacy.FirewallRules[i].Action, compacted.FirewallRules[i].Action,
				"peer %s: rule[%d].Action", peerID, i)
			assert.Equal(t, legacy.FirewallRules[i].Protocol, compacted.FirewallRules[i].Protocol,
				"peer %s: rule[%d].Protocol", peerID, i)
		}
	}

	// Routes
	assert.Equal(t, len(legacy.Routes), len(compacted.Routes),
		"peer %s: Routes count", peerID)

	// Routes firewall rules
	assert.Equal(t, len(legacy.RoutesFirewallRules), len(compacted.RoutesFirewallRules),
		"peer %s: RoutesFirewallRules count", peerID)

	// DNS config
	assert.Equal(t, legacy.DNSConfig.ServiceEnable, compacted.DNSConfig.ServiceEnable,
		"peer %s: DNSConfig.ServiceEnable", peerID)

	// SSH
	assert.Equal(t, legacy.EnableSSH, compacted.EnableSSH,
		"peer %s: EnableSSH", peerID)

	// Authorized users
	assert.Equal(t, len(legacy.AuthorizedUsers), len(compacted.AuthorizedUsers),
		"peer %s: AuthorizedUsers count", peerID)
}

func peerIDSet(peers []*nbpeer.Peer) map[string]struct{} {
	s := make(map[string]struct{}, len(peers))
	for _, p := range peers {
		s[p.ID] = struct{}{}
	}
	return s
}

func normalizeFirewallRules(rules []*types.FirewallRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].PeerIP != rules[j].PeerIP {
			return rules[i].PeerIP < rules[j].PeerIP
		}
		if rules[i].Direction != rules[j].Direction {
			return rules[i].Direction < rules[j].Direction
		}
		if rules[i].Protocol != rules[j].Protocol {
			return rules[i].Protocol < rules[j].Protocol
		}
		return rules[i].Port < rules[j].Port
	})
}

func normalizeNetworkMap(nm *types.NetworkMap) {
	if nm == nil {
		return
	}
	sort.Slice(nm.Peers, func(i, j int) bool { return nm.Peers[i].ID < nm.Peers[j].ID })
	sort.Slice(nm.OfflinePeers, func(i, j int) bool { return nm.OfflinePeers[i].ID < nm.OfflinePeers[j].ID })
	sort.Slice(nm.Routes, func(i, j int) bool { return string(nm.Routes[i].ID) < string(nm.Routes[j].ID) })
	normalizeFirewallRules(nm.FirewallRules)
	sort.Slice(nm.RoutesFirewallRules, func(i, j int) bool {
		if nm.RoutesFirewallRules[i].Destination != nm.RoutesFirewallRules[j].Destination {
			return nm.RoutesFirewallRules[i].Destination < nm.RoutesFirewallRules[j].Destination
		}
		return string(nm.RoutesFirewallRules[i].RouteID) < string(nm.RoutesFirewallRules[j].RouteID)
	})
}

// --- Account builders for various test scenarios ---

func buildSimpleTwoGroupAccount() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-a", 0, 10)
	addGroupWithPeers(account, "group-b", 10, 20)
	addBidirectionalPolicy(account, "policy-ab", "group-a", "group-b")
	return account
}

func buildAllPeersSinglePolicyAccount() *types.Account {
	account := baseAccount(30)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")
	return account
}

func buildMultiPolicyWithPortRules() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-web", 0, 10)
	addGroupWithPeers(account, "group-db", 10, 20)
	addAllGroup(account)

	// Bidirectional ALL
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	// TCP port-specific rule
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-web-db", Name: "Web to DB", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-web-db", Name: "Web->DB TCP", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
			Ports: []string{"5432", "3306"}, Bidirectional: false,
			Sources: []string{"group-web"}, Destinations: []string{"group-db"},
		}},
	})
	return account
}

func buildAccountWithNetworkResources() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-src", 0, 10)
	addGroupWithPeers(account, "group-router", 10, 15)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	network := &networkTypes.Network{ID: "net-1", AccountID: account.Id, Name: "Net 1"}
	account.Networks = append(account.Networks, network)

	routerPeerID := "peer-10"
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID: "router-1", NetworkID: "net-1", AccountID: account.Id, Peer: routerPeerID, Enabled: true,
	})

	resource := &resourceTypes.NetworkResource{
		ID: "res-1", NetworkID: "net-1", AccountID: account.Id, Name: "DB", Type: "host",
		Address: "192.0.2.1/32", Enabled: true,
	}
	account.NetworkResources = append(account.NetworkResources, resource)

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-nr", Name: "NR Policy", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-nr", Name: "NR Rule", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true, Sources: []string{"group-src"},
			DestinationResource: types.Resource{ID: resource.ID},
		}},
	})
	return account
}

func buildAccountWithExpiredPeers() *types.Account {
	account := baseAccount(10)
	addAllGroup(account)

	// Add an expired peer
	peerKey, _ := wgtypes.GeneratePrivateKey()
	pastTime := time.Now().Add(-48 * time.Hour)
	account.Peers["expired-peer"] = &nbpeer.Peer{
		ID: "expired-peer", AccountID: account.Id, DNSLabel: "expired",
		Key: peerKey.PublicKey().String(), IP: net.ParseIP("100.64.10.1"),
		Status: &nbpeer.PeerStatus{LastSeen: time.Now(), Connected: true},
		UserID: "user-1", LoginExpirationEnabled: true, LastLogin: &pastTime,
		Meta: nbpeer.PeerSystemMeta{Hostname: "expired", GoOS: "linux", WtVersion: "dev"},
	}
	account.Groups["all"].Peers = append(account.Groups["all"].Peers, "expired-peer")

	account.Settings.PeerLoginExpirationEnabled = true
	account.Settings.PeerLoginExpiration = 24 * time.Hour

	addBidirectionalPolicy(account, "policy-all", "all", "all")
	return account
}

func buildAccountWithPostureChecks() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-a", 0, 10)
	addGroupWithPeers(account, "group-b", 10, 20)
	addAllGroup(account)

	account.PostureChecks = []*posture.Checks{
		{ID: "pc-1", Name: "Version Check", Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.30.0"},
		}},
	}

	// Policy with posture checks
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-posture", Name: "Posture Policy", Enabled: true,
		SourcePostureChecks: []string{"pc-1"},
		Rules: []*types.PolicyRule{{
			ID: "rule-posture", Name: "Posture Rule", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true, Sources: []string{"group-a"}, Destinations: []string{"group-b"},
		}},
	})

	// Regular policy too
	addBidirectionalPolicy(account, "policy-all", "all", "all")
	return account
}

func buildAccountWithRoutes() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-a", 0, 10)
	addGroupWithPeers(account, "group-b", 10, 20)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	account.Routes = map[route.ID]*route.Route{
		"route-1": {
			ID: "route-1", Network: netip.MustParsePrefix("10.0.0.0/24"),
			PeerID: "peer-5", Peer: account.Peers["peer-5"].Key,
			Enabled: true, Description: "Route 1", AccountID: account.Id,
			Groups: []string{"group-a"}, PeerGroups: []string{"group-a"},
			AccessControlGroups: []string{"group-a"},
		},
		"route-2": {
			ID: "route-2", Network: netip.MustParsePrefix("172.16.0.0/16"),
			PeerID: "peer-15", Peer: account.Peers["peer-15"].Key,
			Enabled: true, Description: "Route 2", AccountID: account.Id,
			Groups: []string{"group-b"}, PeerGroups: []string{"group-b"},
			AccessControlGroups: []string{"all"},
		},
	}
	return account
}

func buildAccountWithDNS() *types.Account {
	account := baseAccount(10)
	addGroupWithPeers(account, "group-a", 0, 5)
	addGroupWithPeers(account, "group-b", 5, 10)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	account.NameServerGroups = map[string]*nbdns.NameServerGroup{
		"ns-1": {
			ID: "ns-1", Name: "Main NS", Enabled: true,
			Groups: []string{"group-a"},
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53},
			},
		},
	}

	// Disable DNS management for group-b
	account.DNSSettings = types.DNSSettings{
		DisabledManagementGroups: []string{"group-b"},
	}
	return account
}

func buildAccountWithOverlappingGroups() *types.Account {
	account := baseAccount(20)

	// Groups with overlapping membership
	addGroupWithPeers(account, "group-a", 0, 12)  // peers 0-11
	addGroupWithPeers(account, "group-b", 8, 20)   // peers 8-19 (overlap: 8-11)
	addGroupWithPeers(account, "group-c", 4, 16)   // peers 4-15 (overlaps both)
	addAllGroup(account)

	addBidirectionalPolicy(account, "policy-ab", "group-a", "group-b")
	addBidirectionalPolicy(account, "policy-bc", "group-b", "group-c")
	addBidirectionalPolicy(account, "policy-ac", "group-a", "group-c")
	return account
}

func buildAccountWithDisabledPolicies() *types.Account {
	account := baseAccount(10)
	addGroupWithPeers(account, "group-a", 0, 5)
	addGroupWithPeers(account, "group-b", 5, 10)
	addAllGroup(account)

	// Active policy
	addBidirectionalPolicy(account, "policy-active", "group-a", "group-b")

	// Disabled policy
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-disabled", Name: "Disabled", Enabled: false,
		Rules: []*types.PolicyRule{{
			ID: "rule-disabled", Name: "Disabled Rule", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true, Sources: []string{"all"}, Destinations: []string{"all"},
		}},
	})

	// Policy with disabled rule
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-disabled-rule", Name: "Disabled Rule Policy", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-disabled-inner", Name: "Disabled Inner Rule", Enabled: false,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true, Sources: []string{"all"}, Destinations: []string{"all"},
		}},
	})
	return account
}

func buildAccountWithDropPolicies() *types.Account {
	account := baseAccount(10)
	addGroupWithPeers(account, "group-a", 0, 5)
	addGroupWithPeers(account, "group-b", 5, 10)
	addAllGroup(account)

	addBidirectionalPolicy(account, "policy-allow", "all", "all")

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-drop", Name: "Drop DB", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-drop", Name: "Drop DB Port", Enabled: true,
			Action: types.PolicyTrafficActionDrop, Protocol: types.PolicyRuleProtocolTCP,
			Ports: []string{"5432"}, Bidirectional: true,
			Sources: []string{"group-a"}, Destinations: []string{"group-b"},
		}},
	})
	return account
}

func buildAccountWithIsolatedPeer() *types.Account {
	account := baseAccount(10)
	addGroupWithPeers(account, "group-connected", 0, 10)

	// Add an isolated peer NOT in any group
	peerKey, _ := wgtypes.GeneratePrivateKey()
	account.Peers["isolated-peer"] = &nbpeer.Peer{
		ID: "isolated-peer", AccountID: account.Id, DNSLabel: "isolated",
		Key: peerKey.PublicKey().String(), IP: net.ParseIP("100.64.10.99"),
		Status: &nbpeer.PeerStatus{LastSeen: time.Now(), Connected: true},
		UserID: "user-1",
		Meta:   nbpeer.PeerSystemMeta{Hostname: "isolated", GoOS: "linux", WtVersion: "dev"},
	}

	addBidirectionalPolicy(account, "policy-connected", "group-connected", "group-connected")
	return account
}

func buildAccountWithUnidirectionalPolicies() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-src", 0, 10)
	addGroupWithPeers(account, "group-dst", 10, 20)
	addAllGroup(account)

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-uni", Name: "Unidirectional", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-uni", Name: "Src->Dst only", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
			Ports: []string{"443"}, Bidirectional: false,
			Sources: []string{"group-src"}, Destinations: []string{"group-dst"},
		}},
	})
	return account
}

func buildAccountWithSSHPolicy() *types.Account {
	account := baseAccount(10)
	addGroupWithPeers(account, "group-ssh-src", 0, 5)
	addGroupWithPeers(account, "group-ssh-dst", 5, 10)
	addAllGroup(account)

	account.Users["user-1"] = &types.User{Id: "user-1", Role: types.UserRoleAdmin}

	addBidirectionalPolicy(account, "policy-all", "all", "all")

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-ssh", Name: "SSH Access", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-ssh", Name: "SSH Rule", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
			Ports: []string{"22"}, Bidirectional: false,
			Sources: []string{"group-ssh-src"}, Destinations: []string{"group-ssh-dst"},
		}},
	})
	return account
}

// --- Base account builder helpers ---

func baseAccount(numPeers int) *types.Account {
	accountID := "test-correctness"
	account := &types.Account{
		Id:     accountID,
		Domain: "test.netbird.io",
		Network: &types.Network{
			Identifier: "net-test",
			Net:        net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.CIDRMask(10, 32)},
			Serial:     1,
		},
		Peers:            make(map[string]*nbpeer.Peer, numPeers),
		Users:            map[string]*types.User{"user-1": {Id: "user-1", Role: types.UserRoleUser}},
		Groups:           make(map[string]*types.Group),
		Policies:         make([]*types.Policy, 0),
		Routes:           make(map[route.ID]*route.Route),
		NameServerGroups: make(map[string]*nbdns.NameServerGroup),
		Settings: &types.Settings{
			PeerLoginExpirationEnabled:      false,
			PeerLoginExpiration:             24 * time.Hour,
			PeerInactivityExpirationEnabled: false,
		},
		Networks:         make([]*networkTypes.Network, 0),
		NetworkRouters:   make([]*routerTypes.NetworkRouter, 0),
		NetworkResources: make([]*resourceTypes.NetworkResource, 0),
	}

	for i := 0; i < numPeers; i++ {
		peerKey, _ := wgtypes.GeneratePrivateKey()
		peerID := fmt.Sprintf("peer-%d", i)
		account.Peers[peerID] = &nbpeer.Peer{
			ID:        peerID,
			AccountID: accountID,
			DNSLabel:  fmt.Sprintf("peer-%d", i),
			Key:       peerKey.PublicKey().String(),
			IP:        net.ParseIP(fmt.Sprintf("100.64.%d.%d", i/256, i%256+1)),
			Status:    &nbpeer.PeerStatus{LastSeen: time.Now(), Connected: true},
			UserID:    "user-1",
			Meta: nbpeer.PeerSystemMeta{
				Hostname: fmt.Sprintf("peer-%d", i), GoOS: "linux",
				WtVersion: "0.25.0",
			},
		}
	}

	return account
}

func addGroupWithPeers(account *types.Account, groupID string, fromPeer, toPeer int) {
	group := &types.Group{ID: groupID, Name: groupID}
	for i := fromPeer; i < toPeer; i++ {
		group.Peers = append(group.Peers, fmt.Sprintf("peer-%d", i))
	}
	account.Groups[groupID] = group
}

func addAllGroup(account *types.Account) {
	allPeers := make([]string, 0, len(account.Peers))
	for peerID := range account.Peers {
		allPeers = append(allPeers, peerID)
	}
	account.Groups["all"] = &types.Group{ID: "all", Name: "All", Peers: allPeers}
}

func addBidirectionalPolicy(account *types.Account, policyID, srcGroup, dstGroup string) {
	account.Policies = append(account.Policies, &types.Policy{
		ID: policyID, Name: policyID, Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-" + policyID, Name: "Rule " + policyID, Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true, Sources: []string{srcGroup}, Destinations: []string{dstGroup},
		}},
	})
}

// --- Additional scenario builders ---

func buildAccountWithMultipleNetworkResources() *types.Account {
	account := baseAccount(30)
	addGroupWithPeers(account, "group-clients", 0, 15)
	addGroupWithPeers(account, "group-servers", 15, 30)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	// Two separate networks, each with a router and resource
	for i, netName := range []string{"db-net", "web-net"} {
		net := &networkTypes.Network{ID: netName, AccountID: account.Id, Name: netName}
		account.Networks = append(account.Networks, net)

		routerPeerID := fmt.Sprintf("peer-%d", 15+i)
		account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
			ID: fmt.Sprintf("router-%s", netName), NetworkID: netName,
			AccountID: account.Id, Peer: routerPeerID, Enabled: true,
		})

		res := &resourceTypes.NetworkResource{
			ID: fmt.Sprintf("res-%s", netName), NetworkID: netName,
			AccountID: account.Id, Name: fmt.Sprintf("Resource %s", netName),
			Type: "host", Address: fmt.Sprintf("192.0.%d.1/32", i+2), Enabled: true,
		}
		account.NetworkResources = append(account.NetworkResources, res)

		account.Policies = append(account.Policies, &types.Policy{
			ID: fmt.Sprintf("policy-nr-%s", netName), Name: fmt.Sprintf("NR %s", netName), Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: fmt.Sprintf("rule-nr-%s", netName), Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
				Bidirectional: true, Sources: []string{"group-clients"},
				DestinationResource: types.Resource{ID: res.ID},
			}},
		})
	}
	return account
}

func buildAccountWithHARoutes() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-a", 0, 10)
	addGroupWithPeers(account, "group-b", 10, 20)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	// Two HA routes for the same network prefix, different metrics
	account.Routes = map[route.ID]*route.Route{
		"route-ha-1": {
			ID: "route-ha-1", Network: netip.MustParsePrefix("10.10.0.0/16"),
			PeerID: "peer-5", Peer: account.Peers["peer-5"].Key,
			Enabled: true, Metric: 100, AccountID: account.Id,
			Groups: []string{"all"}, PeerGroups: []string{"group-a"},
			AccessControlGroups: []string{"all"},
		},
		"route-ha-2": {
			ID: "route-ha-2", Network: netip.MustParsePrefix("10.10.0.0/16"),
			PeerID: "peer-15", Peer: account.Peers["peer-15"].Key,
			Enabled: true, Metric: 200, AccountID: account.Id,
			Groups: []string{"all"}, PeerGroups: []string{"group-b"},
			AccessControlGroups: []string{"all"},
		},
		// Non-HA route
		"route-single": {
			ID: "route-single", Network: netip.MustParsePrefix("172.16.0.0/24"),
			PeerID: "peer-3", Peer: account.Peers["peer-3"].Key,
			Enabled: true, Metric: 100, AccountID: account.Id,
			Groups: []string{"group-a"}, PeerGroups: []string{"group-a"},
		},
	}
	return account
}

func buildAccountWithDisabledRoutesAndResources() *types.Account {
	account := baseAccount(15)
	addGroupWithPeers(account, "group-a", 0, 10)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	// Enabled route
	account.Routes = map[route.ID]*route.Route{
		"route-enabled": {
			ID: "route-enabled", Network: netip.MustParsePrefix("10.0.0.0/24"),
			PeerID: "peer-3", Peer: account.Peers["peer-3"].Key,
			Enabled: true, AccountID: account.Id,
			Groups: []string{"group-a"}, PeerGroups: []string{"group-a"},
		},
		// Disabled route
		"route-disabled": {
			ID: "route-disabled", Network: netip.MustParsePrefix("172.16.0.0/24"),
			PeerID: "peer-5", Peer: account.Peers["peer-5"].Key,
			Enabled: false, AccountID: account.Id,
			Groups: []string{"group-a"}, PeerGroups: []string{"group-a"},
		},
	}

	// Network with disabled resource
	net := &networkTypes.Network{ID: "net-1", AccountID: account.Id, Name: "Net 1"}
	account.Networks = append(account.Networks, net)
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID: "router-1", NetworkID: "net-1", AccountID: account.Id, Peer: "peer-7", Enabled: true,
	})
	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: "res-disabled", NetworkID: "net-1", AccountID: account.Id,
		Name: "Disabled Resource", Type: "host", Address: "192.0.2.1/32", Enabled: false,
	})
	// Enabled resource in same network
	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: "res-enabled", NetworkID: "net-1", AccountID: account.Id,
		Name: "Enabled Resource", Type: "host", Address: "192.0.2.2/32", Enabled: true,
	})
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-nr", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-nr", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
			Sources: []string{"group-a"}, DestinationResource: types.Resource{ID: "res-enabled"},
		}},
	})
	return account
}

func buildAccountWithMultipleNameservers() *types.Account {
	account := baseAccount(15)
	addGroupWithPeers(account, "group-a", 0, 8)
	addGroupWithPeers(account, "group-b", 8, 15)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	account.NameServerGroups = map[string]*nbdns.NameServerGroup{
		"ns-internal": {
			ID: "ns-internal", Name: "Internal DNS", Enabled: true,
			Groups: []string{"group-a"},
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("10.0.0.53"), NSType: nbdns.UDPNameServerType, Port: 53},
			},
			Domains: []string{"internal.corp"},
		},
		"ns-external": {
			ID: "ns-external", Name: "External DNS", Enabled: true,
			Groups: []string{"all"},
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53},
				{IP: netip.MustParseAddr("8.8.4.4"), NSType: nbdns.UDPNameServerType, Port: 53},
			},
			Primary: true,
		},
		"ns-disabled": {
			ID: "ns-disabled", Name: "Disabled NS", Enabled: false,
			Groups: []string{"all"},
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("1.1.1.1"), NSType: nbdns.UDPNameServerType, Port: 53},
			},
		},
	}
	return account
}

func buildAccountWithDNSDisabledManagement() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-managed", 0, 10)
	addGroupWithPeers(account, "group-unmanaged", 10, 20)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	account.DNSSettings = types.DNSSettings{
		DisabledManagementGroups: []string{"group-unmanaged"},
	}
	account.NameServerGroups = map[string]*nbdns.NameServerGroup{
		"ns-1": {
			ID: "ns-1", Name: "Primary NS", Enabled: true, Primary: true,
			Groups: []string{"all"},
			NameServers: []nbdns.NameServer{
				{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53},
			},
		},
	}
	return account
}

func buildAccountWithRoutingPeerPerspective() *types.Account {
	account := baseAccount(10)
	addGroupWithPeers(account, "group-src", 0, 5)
	addGroupWithPeers(account, "group-all-regular", 0, 10)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	// Add a dedicated router peer
	peerKey, _ := wgtypes.GeneratePrivateKey()
	account.Peers["router-peer"] = &nbpeer.Peer{
		ID: "router-peer", AccountID: account.Id, DNSLabel: "router",
		Key: peerKey.PublicKey().String(), IP: net.ParseIP("100.64.10.1"),
		Status: &nbpeer.PeerStatus{LastSeen: time.Now(), Connected: true},
		UserID: "user-1", Meta: nbpeer.PeerSystemMeta{Hostname: "router", GoOS: "linux", WtVersion: "dev"},
	}
	account.Groups["all"].Peers = append(account.Groups["all"].Peers, "router-peer")

	net := &networkTypes.Network{ID: "net-1", AccountID: account.Id, Name: "Net 1"}
	account.Networks = append(account.Networks, net)
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID: "router-1", NetworkID: "net-1", AccountID: account.Id, Peer: "router-peer", Enabled: true,
	})

	res := &resourceTypes.NetworkResource{
		ID: "res-1", NetworkID: "net-1", AccountID: account.Id,
		Name: "Service", Type: "host", Address: "192.0.2.1/32", Enabled: true,
	}
	account.NetworkResources = append(account.NetworkResources, res)

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-nr", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-nr", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
			Sources: []string{"group-src"}, DestinationResource: types.Resource{ID: res.ID},
		}},
	})
	return account
}

func buildAccountWithPeerResourcePolicy() *types.Account {
	account := baseAccount(10)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	// Policy with SourceResource of type peer
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-peer-resource", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-peer-res", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"8080"},
			Bidirectional: true,
			SourceResource: types.Resource{ID: "peer-3", Type: types.ResourceTypePeer},
			Destinations:   []string{"all"},
		}},
	})
	return account
}

func buildAccountWithValidatedPeersExclusion() *types.Account {
	// This tests what happens when some peers are NOT in the validated map
	// (e.g., blocked by integrated validator)
	account := baseAccount(10)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")
	return account
}

func buildAccountWithMultiplePostureChecks() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-a", 0, 10)
	addGroupWithPeers(account, "group-b", 10, 20)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-base", "all", "all")

	account.PostureChecks = []*posture.Checks{
		{ID: "pc-version", Name: "Version Check", Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.30.0"},
		}},
		{ID: "pc-os", Name: "OS Check", Checks: posture.ChecksDefinition{
			OSVersionCheck: &posture.OSVersionCheck{Linux: &posture.MinKernelVersionCheck{MinKernelVersion: "5.0"}},
		}},
	}

	// Policy with first posture check
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-pc1", Enabled: true, SourcePostureChecks: []string{"pc-version"},
		Rules: []*types.PolicyRule{{
			ID: "rule-pc1", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"443"},
			Bidirectional: true, Sources: []string{"group-a"}, Destinations: []string{"group-b"},
		}},
	})

	// Policy with second posture check
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-pc2", Enabled: true, SourcePostureChecks: []string{"pc-os"},
		Rules: []*types.PolicyRule{{
			ID: "rule-pc2", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"22"},
			Bidirectional: false, Sources: []string{"group-b"}, Destinations: []string{"group-a"},
		}},
	})
	return account
}

func buildAccountWithServiceProxyPolicies() *types.Account {
	// Services inject proxy policies into the account before network map calculation.
	// We test with InjectProxyPolicies called explicitly.
	account := baseAccount(10)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")
	return account
}

func buildAccountWithMixedProtocols() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-a", 0, 10)
	addGroupWithPeers(account, "group-b", 10, 20)
	addAllGroup(account)

	// TCP policy
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-tcp", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-tcp", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"80", "443"},
			Bidirectional: true, Sources: []string{"group-a"}, Destinations: []string{"group-b"},
		}},
	})
	// UDP policy
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-udp", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-udp", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolUDP, Ports: []string{"53", "5353"},
			Bidirectional: false, Sources: []string{"group-a"}, Destinations: []string{"group-b"},
		}},
	})
	// ICMP policy
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-icmp", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-icmp", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolICMP, Bidirectional: true,
			Sources: []string{"all"}, Destinations: []string{"all"},
		}},
	})
	// ALL protocol
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-all-proto", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-all-proto", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
			Sources: []string{"group-b"}, Destinations: []string{"group-a"},
		}},
	})
	return account
}

func buildAccountWithPortRanges() *types.Account {
	account := baseAccount(10)
	addGroupWithPeers(account, "group-a", 0, 5)
	addGroupWithPeers(account, "group-b", 5, 10)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-port-range", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-port-range", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolTCP, Bidirectional: true,
			PortRanges: []types.RulePortRange{{Start: 8000, End: 9000}, {Start: 3000, End: 3100}},
			Sources: []string{"group-a"}, Destinations: []string{"group-b"},
		}},
	})
	return account
}

func buildAccountWithManyGroupsAndPolicies() *types.Account {
	account := baseAccount(100)
	addAllGroup(account)

	// Create 20 groups with 5 peers each, plus cross-group policies
	for i := 0; i < 20; i++ {
		gid := fmt.Sprintf("group-%d", i)
		addGroupWithPeers(account, gid, i*5, (i+1)*5)
	}

	// Policy for each adjacent pair
	for i := 0; i < 19; i++ {
		addBidirectionalPolicy(account, fmt.Sprintf("policy-%d-%d", i, i+1),
			fmt.Sprintf("group-%d", i), fmt.Sprintf("group-%d", i+1))
	}
	// Global policy
	addBidirectionalPolicy(account, "policy-all", "all", "all")
	return account
}

func buildAccountWithNRMultipleSourceGroups() *types.Account {
	account := baseAccount(20)
	addGroupWithPeers(account, "group-dev", 0, 7)
	addGroupWithPeers(account, "group-ops", 7, 14)
	addGroupWithPeers(account, "group-admin", 14, 20)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	net := &networkTypes.Network{ID: "net-db", AccountID: account.Id, Name: "DB Net"}
	account.Networks = append(account.Networks, net)
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID: "router-db", NetworkID: "net-db", AccountID: account.Id, Peer: "peer-10", Enabled: true,
	})

	res := &resourceTypes.NetworkResource{
		ID: "res-db", NetworkID: "net-db", AccountID: account.Id,
		Name: "DB", Type: "host", Address: "192.0.2.1/32", Enabled: true,
	}
	account.NetworkResources = append(account.NetworkResources, res)

	// Two separate policies for the same resource from different source groups
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-nr-dev", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-nr-dev", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
			Sources: []string{"group-dev"}, DestinationResource: types.Resource{ID: res.ID},
		}},
	})
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-nr-ops", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-nr-ops", Enabled: true, Action: types.PolicyTrafficActionAccept,
			Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"5432"},
			Bidirectional: true,
			Sources: []string{"group-ops"}, DestinationResource: types.Resource{ID: res.ID},
		}},
	})
	return account
}

func buildAccountWithExpirationVariants() *types.Account {
	account := baseAccount(10)
	addAllGroup(account)
	addBidirectionalPolicy(account, "policy-all", "all", "all")

	// Enable both login and inactivity expiration
	account.Settings.PeerLoginExpirationEnabled = true
	account.Settings.PeerLoginExpiration = 1 * time.Hour
	account.Settings.PeerInactivityExpirationEnabled = true
	account.Settings.PeerInactivityExpiration = 30 * time.Minute

	// One expired peer (login)
	pastLogin := time.Now().Add(-2 * time.Hour)
	account.Peers["peer-8"].LoginExpirationEnabled = true
	account.Peers["peer-8"].LastLogin = &pastLogin

	// One peer with recent login (not expired)
	recentLogin := time.Now().Add(-30 * time.Minute)
	account.Peers["peer-9"].LoginExpirationEnabled = true
	account.Peers["peer-9"].LastLogin = &recentLogin

	return account
}
