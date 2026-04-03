package types

import (
	"net"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
)

// PrecomputedAccountMap holds pre-computed group-level views that allow
// O(groups_per_peer) per-peer network map assembly instead of O(groups * policies).
// Built once per UpdateAccountPeers call, it amortizes the expensive policy
// evaluation across all peers.
type PrecomputedAccountMap struct {
	account         *Account
	validatedPeers  map[string]struct{}
	peerGroupsIndex map[string]LookupMap // peerID -> set of groupIDs

	// groupVisiblePeers maps groupID -> set of peer IDs visible to that group
	// through any policy (either as source seeing destinations, or destinations seeing sources).
	groupVisiblePeers map[string]map[string]struct{}

	// srcGroupEdges maps srcGroupID -> list of (dstGroupID, rules).
	// This avoids scanning all group pairs during per-peer assembly.
	srcGroupEdges map[string][]groupEdge

	// dstGroupEdges maps dstGroupID -> list of (srcGroupID, rules).
	// Used for IN direction rules.
	dstGroupEdges map[string][]groupEdge

	// groupRoutes maps groupID -> routes accessible via distribution groups.
	groupRoutes map[string][]*route.Route

	// peerOwnRoutes maps peerID -> routes where this peer is the routing peer.
	peerOwnRoutes map[string][]*route.Route

	// dnsMgmtDisabled tracks groups where DNS management is disabled.
	dnsMgmtDisabled map[string]struct{}

	// groupNSGroups maps groupID -> nameserver groups applicable.
	groupNSGroups map[string][]*nbdns.NameServerGroup
}

type groupEdge struct {
	targetGroupID string
	rules         []*compactRule
}

// compactRule stores minimal rule metadata for firewall rule generation.
type compactRule struct {
	ruleID    string
	action    string
	protocol  string
	ports     []string
	portRange []RulePortRange
}

// PrecomputeAccountMap builds group-level views. O(policies * groups + routes).
func PrecomputeAccountMap(account *Account, validatedPeers map[string]struct{}) *PrecomputedAccountMap {
	pm := &PrecomputedAccountMap{
		account:           account,
		validatedPeers:    validatedPeers,
		peerGroupsIndex:   account.BuildPeerGroupsIndex(),
		groupVisiblePeers: make(map[string]map[string]struct{}),
		srcGroupEdges:     make(map[string][]groupEdge),
		dstGroupEdges:     make(map[string][]groupEdge),
		groupRoutes:       make(map[string][]*route.Route),
		peerOwnRoutes:     make(map[string][]*route.Route),
		dnsMgmtDisabled:   make(map[string]struct{}),
		groupNSGroups:     make(map[string][]*nbdns.NameServerGroup),
	}

	pm.buildPolicyGraph()
	pm.buildVisibility()
	pm.buildRoutes()
	pm.buildDNS()

	return pm
}

func (pm *PrecomputedAccountMap) buildPolicyGraph() {
	// Collect rules per (src, dst) pair first, then convert to edge lists
	type gp struct{ src, dst string }
	pairRules := make(map[gp][]*compactRule)

	for _, policy := range pm.account.Policies {
		if !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			protocol := rule.Protocol
			if protocol == PolicyRuleProtocolNetbirdSSH {
				protocol = PolicyRuleProtocolTCP
			}

			cr := &compactRule{
				ruleID:   rule.ID,
				action:   string(rule.Action),
				protocol: string(protocol),
				ports:    rule.Ports,
			}
			for _, pr := range rule.PortRanges {
				cr.portRange = append(cr.portRange, RulePortRange{Start: pr.Start, End: pr.End})
			}

			for _, srcGID := range rule.Sources {
				for _, dstGID := range rule.Destinations {
					pair := gp{src: srcGID, dst: dstGID}
					pairRules[pair] = append(pairRules[pair], cr)

					if rule.Bidirectional {
						rev := gp{src: dstGID, dst: srcGID}
						pairRules[rev] = append(pairRules[rev], cr)
					}
				}
			}
		}
	}

	// Convert to indexed edge lists
	for pair, rules := range pairRules {
		pm.srcGroupEdges[pair.src] = append(pm.srcGroupEdges[pair.src], groupEdge{
			targetGroupID: pair.dst,
			rules:         rules,
		})
		pm.dstGroupEdges[pair.dst] = append(pm.dstGroupEdges[pair.dst], groupEdge{
			targetGroupID: pair.src,
			rules:         rules,
		})
	}
}

func (pm *PrecomputedAccountMap) buildVisibility() {
	for srcGID, edges := range pm.srcGroupEdges {
		if pm.groupVisiblePeers[srcGID] == nil {
			pm.groupVisiblePeers[srcGID] = make(map[string]struct{})
		}
		for _, edge := range edges {
			dstGroup := pm.account.Groups[edge.targetGroupID]
			if dstGroup == nil {
				continue
			}
			for _, pid := range dstGroup.Peers {
				if _, ok := pm.validatedPeers[pid]; ok {
					pm.groupVisiblePeers[srcGID][pid] = struct{}{}
				}
			}
		}
	}
}

func (pm *PrecomputedAccountMap) buildRoutes() {
	for _, r := range pm.account.Routes {
		if !r.Enabled {
			continue
		}
		if r.PeerID != "" {
			pm.peerOwnRoutes[r.PeerID] = append(pm.peerOwnRoutes[r.PeerID], r)
		}
		for _, gid := range r.Groups {
			pm.groupRoutes[gid] = append(pm.groupRoutes[gid], r)
		}
	}
}

func (pm *PrecomputedAccountMap) buildDNS() {
	for _, gid := range pm.account.DNSSettings.DisabledManagementGroups {
		pm.dnsMgmtDisabled[gid] = struct{}{}
	}
	for _, ns := range pm.account.NameServerGroups {
		if !ns.Enabled {
			continue
		}
		for _, gid := range ns.Groups {
			pm.groupNSGroups[gid] = append(pm.groupNSGroups[gid], ns)
		}
	}
}

// AssemblePeerNetworkMap builds a NetworkMap from pre-computed group views.
// Per-peer cost: O(groups_per_peer * visible_peers_per_group).
func (pm *PrecomputedAccountMap) AssemblePeerNetworkMap(peerID string) *NetworkMap {
	peer := pm.account.Peers[peerID]
	if peer == nil {
		return &NetworkMap{Network: pm.account.Network.Copy()}
	}
	if _, ok := pm.validatedPeers[peerID]; !ok {
		return &NetworkMap{Network: pm.account.Network.Copy()}
	}

	peerGroups := pm.peerGroupsIndex[peerID]

	// 1. Visible peers (union across all groups this peer is in)
	visiblePeerIDs := make(map[string]struct{})
	for gid := range peerGroups {
		for pid := range pm.groupVisiblePeers[gid] {
			if pid != peerID {
				visiblePeerIDs[pid] = struct{}{}
			}
		}
	}

	// 2. Split active vs expired
	var peers []*nbpeer.Peer
	var expired []*nbpeer.Peer
	checkExpiry := pm.account.Settings.PeerLoginExpirationEnabled

	for pid := range visiblePeerIDs {
		p := pm.account.Peers[pid]
		if p == nil {
			continue
		}
		if checkExpiry {
			if ex, _ := p.LoginExpired(pm.account.Settings.PeerLoginExpiration); ex {
				expired = append(expired, p)
				continue
			}
		}
		peers = append(peers, p)
	}

	// 3. Firewall rules — generated lazily from group-pair rules
	activePeerIPs := make(map[string]string, len(peers)) // peerID -> IP string
	for _, p := range peers {
		activePeerIPs[p.ID] = net.IP(p.IP).String()
	}

	rulesDedup := make(map[fwRuleKey]struct{})
	var fwRules []*FirewallRule

	// OUT rules: this peer is in source group, generate rules for destination peers
	for srcGID := range peerGroups {
		for _, edge := range pm.srcGroupEdges[srcGID] {
			dstGroup := pm.account.Groups[edge.targetGroupID]
			if dstGroup == nil {
				continue
			}
			for _, cr := range edge.rules {
				for _, dstPeerID := range dstGroup.Peers {
					if dstPeerID == peerID {
						continue
					}
					ip, active := activePeerIPs[dstPeerID]
					if !active {
						continue
					}
					pm.addFirewallRules(&fwRules, rulesDedup, cr, ip, FirewallRuleDirectionOUT)
				}
			}
		}
	}

	// IN rules: this peer is in destination group, generate rules for source peers
	for dstGID := range peerGroups {
		for _, edge := range pm.dstGroupEdges[dstGID] {
			srcGroup := pm.account.Groups[edge.targetGroupID]
			if srcGroup == nil {
				continue
			}
			for _, cr := range edge.rules {
				for _, srcPeerID := range srcGroup.Peers {
					if srcPeerID == peerID {
						continue
					}
					ip, active := activePeerIPs[srcPeerID]
					if !active {
						continue
					}
					pm.addFirewallRules(&fwRules, rulesDedup, cr, ip, FirewallRuleDirectionIN)
				}
			}
		}
	}

	// 4. Routes
	haSet := make(LookupMap)
	var routes []*route.Route

	if own, ok := pm.peerOwnRoutes[peerID]; ok {
		for _, r := range own {
			routes = append(routes, r)
			haSet[string(r.GetHAUniqueID())] = struct{}{}
		}
	}

	seenRoutes := make(map[route.ID]struct{})
	for gid := range peerGroups {
		for _, r := range pm.groupRoutes[gid] {
			if _, seen := seenRoutes[r.ID]; seen {
				continue
			}
			seenRoutes[r.ID] = struct{}{}
			if _, ha := haSet[string(r.GetHAUniqueID())]; ha {
				continue
			}
			routes = append(routes, r)
		}
	}

	// 5. DNS
	dnsEnabled := true
	for gid := range peerGroups {
		if _, disabled := pm.dnsMgmtDisabled[gid]; disabled {
			dnsEnabled = false
			break
		}
	}

	dns := nbdns.Config{ServiceEnable: dnsEnabled}
	if dnsEnabled {
		nsSeen := make(map[string]struct{})
		for gid := range peerGroups {
			for _, ns := range pm.groupNSGroups[gid] {
				if _, seen := nsSeen[ns.ID]; !seen {
					nsSeen[ns.ID] = struct{}{}
					dns.NameServerGroups = append(dns.NameServerGroups, ns)
				}
			}
		}
	}

	return &NetworkMap{
		Peers:         peers,
		Network:       pm.account.Network.Copy(),
		Routes:        routes,
		DNSConfig:     dns,
		OfflinePeers:  expired,
		FirewallRules: fwRules,
	}
}

// fwRuleKey is a struct key for deduplication — avoids string concatenation allocations.
type fwRuleKey struct {
	peerIP    string
	ruleID    string
	direction int
	port      string
	portStart uint16
	portEnd   uint16
}

func (pm *PrecomputedAccountMap) addFirewallRules(fwRules *[]*FirewallRule, dedup map[fwRuleKey]struct{}, cr *compactRule, peerIP string, direction int) {
	if len(cr.ports) == 0 && len(cr.portRange) == 0 {
		key := fwRuleKey{peerIP: peerIP, ruleID: cr.ruleID, direction: direction}
		if _, exists := dedup[key]; exists {
			return
		}
		dedup[key] = struct{}{}
		*fwRules = append(*fwRules, &FirewallRule{
			PolicyID: cr.ruleID, PeerIP: peerIP, Direction: direction,
			Action: cr.action, Protocol: cr.protocol,
		})
		return
	}

	for _, port := range cr.ports {
		key := fwRuleKey{peerIP: peerIP, ruleID: cr.ruleID, direction: direction, port: port}
		if _, exists := dedup[key]; exists {
			continue
		}
		dedup[key] = struct{}{}
		*fwRules = append(*fwRules, &FirewallRule{
			PolicyID: cr.ruleID, PeerIP: peerIP, Direction: direction,
			Action: cr.action, Protocol: cr.protocol, Port: port,
		})
	}

	for _, pr := range cr.portRange {
		key := fwRuleKey{peerIP: peerIP, ruleID: cr.ruleID, direction: direction, portStart: pr.Start, portEnd: pr.End}
		if _, exists := dedup[key]; exists {
			continue
		}
		dedup[key] = struct{}{}
		*fwRules = append(*fwRules, &FirewallRule{
			PolicyID: cr.ruleID, PeerIP: peerIP, Direction: direction,
			Action: cr.action, Protocol: cr.protocol, PortRange: pr,
		})
	}
}

// AllPeerIDs returns all peer IDs for iteration.
func (pm *PrecomputedAccountMap) AllPeerIDs() []string {
	ids := make([]string, 0, len(pm.account.Peers))
	for id := range pm.account.Peers {
		ids = append(ids, id)
	}
	return ids
}
