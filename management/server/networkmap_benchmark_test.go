package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// BenchmarkNetworkMapLargeScale benchmarks network map calculation and peer update
// for accounts with 10K-30K connected peers, representing real-world large deployments.
func BenchmarkNetworkMapLargeScale(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"10K_peers_50_groups", 10000, 50},
		{"10K_peers_200_groups", 10000, 200},
		{"20K_peers_100_groups", 20000, 100},
		{"20K_peers_500_groups", 20000, 500},
		{"30K_peers_100_groups", 30000, 100},
		{"30K_peers_500_groups", 30000, 500},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, updateManager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}

			ctx := context.Background()

			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}

			for peerID := range account.Peers {
				updateManager.CreateChannel(ctx, peerID)
			}

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				manager.UpdateAccountPeers(ctx, account.Id)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")
			b.ReportMetric(float64(len(account.Peers)), "peers")
			b.ReportMetric(float64(bc.groups), "groups")
		})
	}
}

// BenchmarkGetPeerNetworkMapIsolated benchmarks the per-peer network map calculation
// in isolation (without the update channel broadcast). This isolates the core
// algorithmic performance from I/O and serialization costs.
func BenchmarkGetPeerNetworkMapIsolated(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"Small_50p_5g", 50, 5},
		{"Medium_500p_100g", 500, 100},
		{"Large_5000p_200g", 5000, 200},
		{"XLarge_10000p_200g", 10000, 200},
		{"XXLarge_20000p_100g", 20000, 100},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name+"/legacy", func(b *testing.B) {
			benchGetPeerNetworkMap(b, bc.peers, bc.groups, "legacy")
		})
		b.Run(bc.name+"/compacted", func(b *testing.B) {
			benchGetPeerNetworkMap(b, bc.peers, bc.groups, "compacted")
		})
	}
}

func benchGetPeerNetworkMap(b *testing.B, peers, groups int, mode string) {
	b.Helper()

	account := buildLargeAccount(b, peers, groups)

	validatedPeersMap := make(map[string]struct{}, len(account.Peers))
	for peerID := range account.Peers {
		validatedPeersMap[peerID] = struct{}{}
	}

	peersCustomZone := nbdns.CustomZone{
		Domain: "netbird.cloud.",
	}

	resourcePolicies := account.GetResourcePoliciesMap()
	routers := account.GetResourceRoutersMap()
	groupIDToUserIDs := account.GetActiveGroupUsers()
	peerGroupsIndex := account.BuildPeerGroupsIndex()

	// Pick a target peer in the middle of the account
	targetPeerID := fmt.Sprintf("peer-%d", peers/2)

	b.ResetTimer()

	var memBefore, memAfter runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		switch mode {
		case "legacy":
			account.GetPeerNetworkMap(ctx, targetPeerID, peersCustomZone, nil, validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs)
		case "compacted":
			account.GetPeerNetworkMapFromComponents(ctx, targetPeerID, peersCustomZone, nil, validatedPeersMap, resourcePolicies, routers, nil, groupIDToUserIDs, peerGroupsIndex)
		}
	}

	runtime.ReadMemStats(&memAfter)
	b.ReportMetric(float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/float64(b.N), "bytes/op")
}

// BenchmarkGetPeerConnectionResources benchmarks the ACL evaluation which is
// the core O(peers * policies * groups) hot path.
func BenchmarkGetPeerConnectionResources(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"Small_50p_5g", 50, 5},
		{"Medium_500p_100g", 500, 100},
		{"Large_5000p_200g", 5000, 200},
		{"XLarge_10000p_50g", 10000, 50},
		{"XXLarge_20000p_100g", 20000, 100},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			account := buildLargeAccount(b, bc.peers, bc.groups)

			validatedPeersMap := make(map[string]struct{}, len(account.Peers))
			for peerID := range account.Peers {
				validatedPeersMap[peerID] = struct{}{}
			}

			groupIDToUserIDs := account.GetActiveGroupUsers()

			targetPeerID := fmt.Sprintf("peer-%d", bc.peers/2)
			targetPeer := account.Peers[targetPeerID]

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				account.GetPeerConnectionResources(context.Background(), targetPeer, validatedPeersMap, groupIDToUserIDs)
			}
		})
	}
}

// BenchmarkFullUpdateCycleAllPeers benchmarks the full cycle of computing
// network maps for ALL peers in an account (what happens on UpdateAccountPeers).
// This measures the O(n^2) cost: for each of n peers, we compute their network map.
func BenchmarkFullUpdateCycleAllPeers(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"1K_peers_50g", 1000, 50},
		{"5K_peers_100g", 5000, 100},
		{"10K_peers_100g", 10000, 100},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			account := buildLargeAccount(b, bc.peers, bc.groups)

			validatedPeersMap := make(map[string]struct{}, len(account.Peers))
			for peerID := range account.Peers {
				validatedPeersMap[peerID] = struct{}{}
			}

			peersCustomZone := nbdns.CustomZone{Domain: "netbird.cloud."}
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			peerGroupsIdx := account.BuildPeerGroupsIndex()

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				for _, peer := range account.Peers {
					account.GetPeerNetworkMapFromComponents(
						context.Background(),
						peer.ID,
						peersCustomZone,
						nil,
						validatedPeersMap,
						resourcePolicies,
						routers,
						nil,
						groupIDToUserIDs,
						peerGroupsIdx,
					)
				}
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op(all-peers)")
			perPeerUs := msPerOp * 1000 / float64(bc.peers)
			b.ReportMetric(perPeerUs, "us/peer")
		})
	}
}

// BenchmarkNetworkMapScaling measures how network map computation scales with peer count.
// This helps identify O(n^2) vs O(n*log(n)) vs O(n) behavior.
func BenchmarkNetworkMapScaling(b *testing.B) {
	peerCounts := []int{100, 500, 1000, 2000, 5000, 10000}
	groupRatio := 20 // peers/groups

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, pc := range peerCounts {
		groups := pc / groupRatio
		if groups < 1 {
			groups = 1
		}

		b.Run(fmt.Sprintf("%d_peers", pc), func(b *testing.B) {
			account := buildLargeAccount(b, pc, groups)

			validatedPeersMap := make(map[string]struct{}, len(account.Peers))
			for peerID := range account.Peers {
				validatedPeersMap[peerID] = struct{}{}
			}

			peersCustomZone := nbdns.CustomZone{Domain: "netbird.cloud."}
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			pgIdx := account.BuildPeerGroupsIndex()

			targetPeerID := fmt.Sprintf("peer-%d", pc/2)

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				account.GetPeerNetworkMapFromComponents(
					context.Background(),
					targetPeerID,
					peersCustomZone,
					nil,
					validatedPeersMap,
					resourcePolicies,
					routers,
					nil,
					groupIDToUserIDs,
					pgIdx,
				)
			}
		})
	}
}

// BenchmarkUpdateAccountPeersExperimental runs UpdateAccountPeers with the experimental
// network map builder enabled, allowing comparison with the default mode.
func BenchmarkUpdateAccountPeersExperimental(b *testing.B) {
	b.Setenv(network_map.EnvNewNetworkMapBuilder, "true")

	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"Small_50p", 50, 5},
		{"Medium_500p", 500, 100},
		{"Large_5000p", 5000, 200},
		{"XLarge_10000p", 10000, 200},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			manager, updateManager, accountID, _, err := setupTestAccountManager(b, bc.peers, bc.groups)
			if err != nil {
				b.Fatalf("Failed to setup test account manager: %v", err)
			}

			ctx := context.Background()
			account, err := manager.Store.GetAccount(ctx, accountID)
			if err != nil {
				b.Fatalf("Failed to get account: %v", err)
			}

			for peerID := range account.Peers {
				updateManager.CreateChannel(ctx, peerID)
			}

			// Warm up - first call builds the cache
			manager.UpdateAccountPeers(ctx, account.Id)

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				manager.UpdateAccountPeers(ctx, account.Id)
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op")
		})
	}
}

// BenchmarkGroupMembershipLookup benchmarks the group membership lookups which
// are a key hotspot in policy evaluation at scale.
func BenchmarkGroupMembershipLookup(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"Small_50p_5g", 50, 5},
		{"Large_5000p_200g", 5000, 200},
		{"XLarge_10000p_500g", 10000, 500},
		{"XXLarge_20000p_1000g", 20000, 1000},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			account := buildLargeAccount(b, bc.peers, bc.groups)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, group := range account.Groups {
					for _, peerID := range group.Peers {
						_ = account.Peers[peerID]
					}
				}
			}
		})
	}
}

// BenchmarkPeerGroupsLookup benchmarks GetPeerGroups which is called per-peer
// during network map calculation.
func BenchmarkPeerGroupsLookup(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"Large_5000p_200g", 5000, 200},
		{"XLarge_10000p_500g", 10000, 500},
		{"XXLarge_20000p_1000g", 20000, 1000},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			account := buildLargeAccount(b, bc.peers, bc.groups)

			targetPeerID := fmt.Sprintf("peer-%d", bc.peers/2)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				account.GetPeerGroups(targetPeerID)
			}
		})
	}
}

// buildLargeAccount creates an Account with the specified number of peers and groups,
// with realistic policy and network resource structures.
func buildLargeAccount(tb testing.TB, numPeers, numGroups int) *types.Account {
	tb.Helper()

	accountID := "bench_account"
	adminUser := "admin_user"
	regularUser := "regular_user"

	account := &types.Account{
		Id:               accountID,
		CreatedBy:        adminUser,
		Domain:           "bench.netbird.io",
		DomainCategory:   types.PrivateCategory,
		IsDomainPrimaryAccount: true,
		Network: &types.Network{
			Identifier: "bench_net",
			Net:        net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.CIDRMask(10, 32)},
			Serial:     0,
		},
		Peers:              make(map[string]*nbpeer.Peer, numPeers+numGroups),
		Users:              make(map[string]*types.User, 2),
		Groups:             make(map[string]*types.Group, numGroups+1),
		Policies:           make([]*types.Policy, 0, numGroups*2),
		Routes:             make(map[route.ID]*route.Route),
		NameServerGroups:   make(map[string]*nbdns.NameServerGroup),
		Networks:           make([]*networkTypes.Network, 0, numGroups),
		NetworkRouters:     make([]*routerTypes.NetworkRouter, 0, numGroups),
		NetworkResources:   make([]*resourceTypes.NetworkResource, 0, numGroups),
		Settings: &types.Settings{
			PeerLoginExpirationEnabled:      true,
			PeerLoginExpiration:             24 * time.Hour,
			PeerInactivityExpirationEnabled: false,
		},
		PostureChecks: []*posture.Checks{
			{
				ID:   "PostureChecksAll",
				Name: "All",
				Checks: posture.ChecksDefinition{
					NBVersionCheck: &posture.NBVersionCheck{
						MinVersion: "0.0.1",
					},
				},
			},
		},
	}

	account.Users[adminUser] = &types.User{
		Id:            adminUser,
		Role:          types.UserRoleAdmin,
		IsServiceUser: false,
	}
	account.Users[regularUser] = &types.User{
		Id:            regularUser,
		Role:          types.UserRoleUser,
		IsServiceUser: false,
	}

	// Create "all" group
	allGroup := &types.Group{
		ID:    "all",
		Name:  "All",
		Peers: make([]string, 0, numPeers+numGroups),
	}

	// Create peers
	for i := 0; i < numPeers; i++ {
		peerKey, _ := wgtypes.GeneratePrivateKey()
		peerID := fmt.Sprintf("peer-%d", i)
		peer := &nbpeer.Peer{
			ID:        peerID,
			AccountID: accountID,
			DNSLabel:  fmt.Sprintf("peer-%d", i),
			Key:       peerKey.PublicKey().String(),
			IP:        net.ParseIP(fmt.Sprintf("100.64.%d.%d", (i/256)%256, i%256)),
			Status:    &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
			UserID:    regularUser,
			Meta: nbpeer.PeerSystemMeta{
				Hostname:  fmt.Sprintf("peer-%d", i),
				GoOS:      "linux",
				Kernel:    "Linux",
				Core:      "21.04",
				Platform:  "x86_64",
				OS:        "Ubuntu",
				WtVersion: "development",
				UIVersion: "development",
			},
		}
		account.Peers[peerID] = peer
		allGroup.Peers = append(allGroup.Peers, peerID)
	}

	// Create groups, policies, and network resources
	for i := 0; i < numGroups; i++ {
		groupID := fmt.Sprintf("group-%d", i)
		group := &types.Group{
			ID:   groupID,
			Name: fmt.Sprintf("Group %d", i),
		}

		peersPerGroup := numPeers / numGroups
		for j := 0; j < peersPerGroup; j++ {
			peerIndex := i*peersPerGroup + j
			group.Peers = append(group.Peers, fmt.Sprintf("peer-%d", peerIndex))
		}

		// Create network and router for each group
		network := &networkTypes.Network{
			ID:        fmt.Sprintf("network-%d", i),
			AccountID: accountID,
			Name:      fmt.Sprintf("Network for Group %d", i),
		}
		account.Networks = append(account.Networks, network)

		peerKey, _ := wgtypes.GeneratePrivateKey()
		routerPeerID := fmt.Sprintf("peer-nr-%d", numPeers+i)
		routerPeer := &nbpeer.Peer{
			ID:        routerPeerID,
			AccountID: accountID,
			DNSLabel:  routerPeerID,
			Key:       peerKey.PublicKey().String(),
			IP:        net.ParseIP(fmt.Sprintf("100.65.%d.%d", (i/256)%256, i%256)),
			Status:    &nbpeer.PeerStatus{LastSeen: time.Now().UTC(), Connected: true},
			UserID:    regularUser,
			Meta: nbpeer.PeerSystemMeta{
				Hostname:  routerPeerID,
				GoOS:      "linux",
				Kernel:    "Linux",
				Core:      "21.04",
				Platform:  "x86_64",
				OS:        "Ubuntu",
				WtVersion: "development",
				UIVersion: "development",
			},
		}
		account.Peers[routerPeerID] = routerPeer
		group.Peers = append(group.Peers, routerPeerID)
		allGroup.Peers = append(allGroup.Peers, routerPeerID)
		account.Groups[groupID] = group

		router := &routerTypes.NetworkRouter{
			ID:         fmt.Sprintf("network-router-%d", i),
			NetworkID:  network.ID,
			AccountID:  accountID,
			Peer:       routerPeerID,
			PeerGroups: []string{},
			Masquerade: false,
			Metric:     9999,
		}
		account.NetworkRouters = append(account.NetworkRouters, router)

		resource := &resourceTypes.NetworkResource{
			ID:        fmt.Sprintf("network-resource-%d", i),
			NetworkID: network.ID,
			AccountID: accountID,
			Name:      fmt.Sprintf("Resource for Group %d", i),
			Type:      "host",
			Address:   "192.0.2.0/32",
			Enabled:   true,
		}
		account.NetworkResources = append(account.NetworkResources, resource)

		// Network resource policy
		nrPolicy := &types.Policy{
			ID:      fmt.Sprintf("policy-nr-%d", i),
			Name:    fmt.Sprintf("NR Policy %d", i),
			Enabled: true,
			Rules: []*types.PolicyRule{
				{
					ID:            fmt.Sprintf("rule-nr-%d", i),
					Name:          fmt.Sprintf("NR Rule %d", i),
					Enabled:       true,
					Sources:       []string{groupID},
					Destinations:  []string{},
					DestinationResource: types.Resource{ID: resource.ID},
					Bidirectional: true,
					Protocol:      types.PolicyRuleProtocolALL,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}
		account.Policies = append(account.Policies, nrPolicy)

		// Peer-to-peer policy
		policy := &types.Policy{
			ID:      fmt.Sprintf("policy-%d", i),
			Name:    fmt.Sprintf("Policy %d", i),
			Enabled: true,
			Rules: []*types.PolicyRule{
				{
					ID:            fmt.Sprintf("rule-%d", i),
					Name:          fmt.Sprintf("Rule %d", i),
					Enabled:       true,
					Sources:       []string{groupID},
					Destinations:  []string{groupID},
					Bidirectional: true,
					Protocol:      types.PolicyRuleProtocolALL,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}
		account.Policies = append(account.Policies, policy)
	}

	account.Groups["all"] = allGroup

	return account
}

// BenchmarkMemoryPerNetworkMap measures memory allocation per network map computation
// at various scales.
func BenchmarkMemoryPerNetworkMap(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"1K_peers", 1000, 50},
		{"5K_peers", 5000, 200},
		{"10K_peers", 10000, 200},
		{"20K_peers", 20000, 500},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			account := buildLargeAccount(b, bc.peers, bc.groups)

			validatedPeersMap := make(map[string]struct{}, len(account.Peers))
			for peerID := range account.Peers {
				validatedPeersMap[peerID] = struct{}{}
			}

			peersCustomZone := nbdns.CustomZone{Domain: "netbird.cloud."}
			resourcePolicies := account.GetResourcePoliciesMap()
			routers := account.GetResourceRoutersMap()
			groupIDToUserIDs := account.GetActiveGroupUsers()
			pgIdx := account.BuildPeerGroupsIndex()

			targetPeerID := fmt.Sprintf("peer-%d", bc.peers/2)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				account.GetPeerNetworkMapFromComponents(
					context.Background(),
					targetPeerID,
					peersCustomZone,
					nil,
					validatedPeersMap,
					resourcePolicies,
					routers,
					nil,
					groupIDToUserIDs,
					pgIdx,
				)
			}
		})
	}
}

// BenchmarkPrecomputedNetworkMap benchmarks the pre-computed group-level approach
// where we build group views once and assemble per-peer maps from them.
func BenchmarkPrecomputedNetworkMap(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"1K_peers_50g", 1000, 50},
		{"5K_peers_100g", 5000, 100},
		{"10K_peers_100g", 10000, 100},
		{"20K_peers_100g", 20000, 100},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			account := buildLargeAccount(b, bc.peers, bc.groups)

			validatedPeersMap := make(map[string]struct{}, len(account.Peers))
			for peerID := range account.Peers {
				validatedPeersMap[peerID] = struct{}{}
			}

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				pm := types.PrecomputeAccountMap(account, validatedPeersMap)
				for _, peerID := range pm.AllPeerIDs() {
					pm.AssemblePeerNetworkMap(peerID)
				}
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op(all-peers)")
			perPeerUs := msPerOp * 1000 / float64(bc.peers+bc.groups)
			b.ReportMetric(perPeerUs, "us/peer")
		})
	}
}

// BenchmarkPrecomputedNetworkMap_Segmented benchmarks the pre-computed approach
// with segmented policies (peers only see their own group), which is more realistic
// for large deployments where not every peer talks to every other peer.
func BenchmarkPrecomputedNetworkMap_Segmented(b *testing.B) {
	benchCases := []struct {
		name   string
		peers  int
		groups int
	}{
		{"5K_peers_100g_segmented", 5000, 100},
		{"10K_peers_200g_segmented", 10000, 200},
		{"20K_peers_500g_segmented", 20000, 500},
		{"30K_peers_500g_segmented", 30000, 500},
	}

	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, bc := range benchCases {
		b.Run(bc.name, func(b *testing.B) {
			account := buildSegmentedAccount(bc.peers, bc.groups)

			validatedPeersMap := make(map[string]struct{}, len(account.Peers))
			for peerID := range account.Peers {
				validatedPeersMap[peerID] = struct{}{}
			}

			b.ResetTimer()
			start := time.Now()

			for i := 0; i < b.N; i++ {
				pm := types.PrecomputeAccountMap(account, validatedPeersMap)
				for _, peerID := range pm.AllPeerIDs() {
					pm.AssemblePeerNetworkMap(peerID)
				}
			}

			duration := time.Since(start)
			msPerOp := float64(duration.Nanoseconds()) / float64(b.N) / 1e6
			b.ReportMetric(msPerOp, "ms/op(all-peers)")
			perPeerUs := msPerOp * 1000 / float64(len(account.Peers))
			b.ReportMetric(perPeerUs, "us/peer")
		})
	}
}

// buildSegmentedAccount creates an account where each group has its own policy
// (peers only talk to peers in their own group + one cross-group policy).
// This is realistic for large enterprise deployments with segmented networks.
func buildSegmentedAccount(numPeers, numGroups int) *types.Account {
	account := &types.Account{
		Id:     "bench-segmented",
		Domain: "bench.netbird.io",
		Network: &types.Network{
			Identifier: "net-bench",
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
			PeerLoginExpirationEnabled: false,
			PeerLoginExpiration:        24 * time.Hour,
		},
	}

	// Create peers
	for i := 0; i < numPeers; i++ {
		peerKey, _ := wgtypes.GeneratePrivateKey()
		peerID := fmt.Sprintf("peer-%d", i)
		account.Peers[peerID] = &nbpeer.Peer{
			ID: peerID, AccountID: account.Id, DNSLabel: peerID,
			Key:    peerKey.PublicKey().String(),
			IP:     net.ParseIP(fmt.Sprintf("100.64.%d.%d", (i/256)%256, i%256+1)),
			Status: &nbpeer.PeerStatus{LastSeen: time.Now(), Connected: true},
			UserID: "user-1",
			Meta:   nbpeer.PeerSystemMeta{Hostname: peerID, GoOS: "linux", WtVersion: "dev"},
		}
	}

	// Create segmented groups (each peer in exactly ONE group)
	peersPerGroup := numPeers / numGroups
	for i := 0; i < numGroups; i++ {
		gid := fmt.Sprintf("group-%d", i)
		group := &types.Group{ID: gid, Name: gid}
		for j := 0; j < peersPerGroup; j++ {
			idx := i*peersPerGroup + j
			group.Peers = append(group.Peers, fmt.Sprintf("peer-%d", idx))
		}
		account.Groups[gid] = group

		// Intra-group policy: peers in group can talk to each other
		account.Policies = append(account.Policies, &types.Policy{
			ID: fmt.Sprintf("policy-%d", i), Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: fmt.Sprintf("rule-%d", i), Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
				Bidirectional: true, Sources: []string{gid}, Destinations: []string{gid},
			}},
		})
	}

	return account
}

// Ensure imports are used
var _ = maps.Keys[map[string]struct{}]
