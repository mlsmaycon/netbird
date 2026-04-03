# Network Map Calculation Performance Optimization

## Overview

This document describes the performance analysis and optimization work done on
the NetBird management server's network map calculation and peer update
pipeline. The goal was to evaluate performance at 20-30K connected peers and
achieve sub-second update cycles.

## Architecture Background

When a change occurs in an account (policy update, peer added/removed, route
change, etc.), the management server must recompute and distribute a
**NetworkMap** to every connected peer. Each NetworkMap contains:

- **Peers**: list of peers this peer can communicate with
- **FirewallRules**: ACL rules (one per visible peer per policy rule)
- **Routes**: network routes accessible to this peer
- **RoutesFirewallRules**: access control rules for routes
- **DNSConfig**: nameserver groups and custom zones
- **OfflinePeers**: expired/inactive peers
- **AuthorizedUsers**: SSH authorization mappings

The server has three calculation strategies:
1. **Legacy** (`GetPeerNetworkMap`): direct calculation per peer
2. **Compacted** (`GetPeerNetworkMapFromComponents`): component-based, default mode
3. **Experimental** (`NetworkMapBuilder`): incremental caching via `NB_EXPERIMENT_NETWORK_MAP`

All three share the same fundamental design: for each of N peers, independently
evaluate all policies, groups, and routes to build that peer's view.

## The Problem

The `UpdateAccountPeers` function computes a NetworkMap for every connected
peer in an account. The cost scales as:

```
Total cost = N_peers × cost_per_peer
cost_per_peer = O(policies × groups × peers_per_group)
```

This creates **O(N²)** or worse total complexity because `cost_per_peer` itself
grows with the number of peers.

### Baseline Performance (4-core Xeon @ 2.10GHz)

| Peers | Groups | UpdateAccountPeers |
|-------|--------|--------------------|
| 1K    | 50     | 293ms              |
| 5K    | 200    | 3.4s               |
| 5K    | 15     | 7.2s               |
| 10K   | 50     | 28.0s              |
| 20K   | 100    | 92.4s              |

At 20K peers, a single `UpdateAccountPeers` call takes **over 90 seconds**.

## Profiling Analysis

CPU profiling of the 5K peer benchmark revealed the cost breakdown:

| Function | % CPU | Description |
|----------|-------|-------------|
| `getPeersFromGroups` | 59% | Iterates group members per policy per peer |
| `mapaccess2_faststr` | 51% | String-keyed map lookups (Go runtime) |
| GC (`gcDrain`, `scanobject`) | 22% | Garbage collection from map/slice allocations |
| `validatePostureChecksOnPeerGetFailed` | 9% | Posture check validation per peer |
| `getPeerConnectionResources` | 7% | Firewall rule generation |

### Root Causes

1. **Redundant group membership scans**: `GetPeerGroups` uses
   `slices.Contains(group.Peers, peerID)` — O(groups × peers_per_group) per
   call, called multiple times per peer.

2. **Per-peer policy re-evaluation**: `getPeersGroupsPoliciesRoutes` iterates
   ALL groups and ALL policies for EACH peer independently, even though peers
   in the same group get the same policy evaluation result.

3. **Excessive map allocations**: each peer's computation creates fresh maps
   for deduplication, group lookups, and results — generating millions of
   short-lived objects that pressure the GC.

4. **String concatenation for dedup keys**: firewall rule deduplication uses
   string concatenation (`ruleID + peerIP + direction + ...`), creating
   temporary strings that become garbage.

## Optimization 1: Peer-to-Groups Reverse Index

**Branch**: `benchmark-network-map`

### Approach

Added `BuildPeerGroupsIndex()` that creates a `map[peerID]map[groupID]struct{}`
reverse index in a single O(total_group_members) pass. This index is built once
per `UpdateAccountPeers` call and passed through the calculation pipeline.

### Changes

- `account.go`: Added `BuildPeerGroupsIndex()` and `GetPeerGroupsFromIndex()`
- `account_components.go`: Updated `getPeersGroupsPoliciesRoutes` to use index
  for O(1) group membership lookup instead of `slices.Contains`
- `networkmap_components.go`: Updated `GetPeerGroups` and `IsPeerInGroup` on
  `NetworkMapComponents` to use the index
- `controller.go`: Build index once in `sendUpdateAccountPeers` and pass to
  both legacy and compacted paths
- `account_components.go`: Added early return in
  `validatePostureChecksOnPeerGetFailed` when no posture checks configured
- `account_components.go`: Reduced redundant `a.Peers[pid]` map lookups in
  `getPeersFromGroups` by checking `validatedPeersMap` directly

### Results

| Peers | Before | After | Speedup |
|-------|--------|-------|---------|
| 1K    | 293ms  | 182ms | 1.6x    |
| 5K    | 6.3s   | 3.3s  | 1.9x    |
| 10K   | 26.0s  | 12.8s | 2.0x    |
| 20K   | 92.4s  | 29.5s | 3.1x    |

## Optimization 2: Pre-computed Group-Level Network Maps

**Branch**: `benchmark-network-map-subsecond`

### Key Insight

All peers in the same group get the **same set of visible peers** and the
**same firewall rule templates** — only the peer's own IP differs. The current
approach recomputes this N times when it could be computed once per group.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  PrecomputeAccountMap                     │
│                  (built once per update cycle)            │
│                                                          │
│  ┌──────────────────┐  ┌──────────────────────────────┐ │
│  │  Policy Graph     │  │  Group Visibility             │ │
│  │                   │  │                               │ │
│  │  srcGroup ──edge──│  │  groupID → {visible peerIDs} │ │
│  │     │     rules   │  │                               │ │
│  │  dstGroup         │  │  Built from policy graph      │ │
│  └──────────────────┘  │  edges (src sees dst peers,   │ │
│                         │  dst sees src peers)          │ │
│  ┌──────────────────┐  └──────────────────────────────┘ │
│  │  Group Routes     │  ┌──────────────────────────────┐ │
│  │                   │  │  DNS per Group                │ │
│  │  groupID → routes │  │                               │ │
│  │  peerID → own     │  │  mgmt enabled/disabled        │ │
│  │           routes  │  │  nameserver groups             │ │
│  └──────────────────┘  └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              AssemblePeerNetworkMap(peerID)               │
│              (called per peer, O(groups_per_peer))        │
│                                                          │
│  1. Look up peer's groups          ── O(1) index lookup  │
│  2. Union visible peers from       ── O(groups × visible)│
│     all group views                                      │
│  3. Generate firewall rules from   ── O(edges × peers)   │
│     group-pair rules + peer IPs                          │
│  4. Collect routes from groups     ── O(groups × routes) │
│  5. Determine DNS settings         ── O(groups)          │
│  6. Delegate RoutesFirewallRules   ── O(own_routes)      │
└─────────────────────────────────────────────────────────┘
```

### Phase 1: Pre-computation (`PrecomputeAccountMap`)

Built once per `UpdateAccountPeers` call. Cost: O(policies × groups + routes).

#### Policy Graph (`buildPolicyGraph`)

For each enabled policy rule, creates edges between source and destination
groups with the applicable rule metadata attached:

```go
type groupEdge struct {
    targetGroupID string
    rules         []*compactRule  // ruleID, action, protocol, ports
}

// Indexed by source group for OUT rules
srcGroupEdges map[string][]groupEdge

// Indexed by destination group for IN rules
dstGroupEdges map[string][]groupEdge
```

Bidirectional rules create edges in both directions. Unidirectional rules
create edges only in the specified direction.

#### Group Visibility (`buildVisibility`)

For each edge in the policy graph, marks destination group peers as visible
to source group members (and vice versa for IN direction):

```go
groupVisiblePeers map[string]map[string]struct{}
```

This means: "any peer in groupX can see all peers in this set."

#### Group Routes (`buildRoutes`)

Maps each group to the routes distributed to it, and tracks per-peer own
routes for routing peers:

```go
groupRoutes   map[string][]*route.Route
peerOwnRoutes map[string][]*route.Route
```

#### DNS (`buildDNS`)

Pre-computes which groups have DNS management disabled and which nameserver
groups apply to each group.

### Phase 2: Per-Peer Assembly (`AssemblePeerNetworkMap`)

For each peer, the assembly is O(groups_per_peer × visible_peers_per_group):

1. **Visible peers**: union of `groupVisiblePeers[g]` for each group `g` the
   peer belongs to. Exclude self.

2. **Peer list split**: separate visible peers into active vs expired based on
   `PeerLoginExpiration` settings.

3. **Firewall rules**: iterate the peer's source group edges (OUT) and
   destination group edges (IN). For each edge, iterate the target group's
   peers and generate rules using the compact rule metadata. Rules are
   deduplicated using struct keys (avoiding string concatenation).

4. **Routes**: collect own routes first (for routing peers), then union group
   routes with HA deduplication.

5. **DNS**: check if any of the peer's groups has DNS management disabled.
   Collect applicable nameserver groups.

6. **RoutesFirewallRules**: delegated to existing `GetPeerRoutesFirewallRules`
   (only applies to routing peers, small cost).

### Port Range Handling

Firewall rules with port ranges are expanded based on the viewing peer's
client version:
- Version >= 0.48.0: port ranges sent as-is (`PortRange` field)
- Version < 0.48.0: only single-port ranges expanded (matching legacy behavior)

### Results

#### Segmented Policies (realistic enterprise deployment)

Each group has its own intra-group policy. Peers only see peers in their own
group.

| Peers  | Groups | Precompute | Assembly | Total      | vs Baseline |
|--------|--------|------------|----------|------------|-------------|
| 5K     | 100    | 2.0ms      | 239ms    | **241ms**  | 26x faster  |
| 10K    | 200    | 6.2ms      | 462ms    | **468ms**  | 56x faster  |
| **20K**| **500**| **15ms**   | **812ms**| **827ms**  | **112x**    |
| 30K    | 500    | 26ms       | 1.85s    | **1.88s**  | ~100x       |

#### All-to-All Policies (worst case)

Single policy connecting all peers to all peers. Each peer sees every other
peer.

| Peers | Groups | Precompute | Assembly | Total     | vs Baseline |
|-------|--------|------------|----------|-----------|-------------|
| 1K    | 50     | 0.85ms     | 25ms     | **25ms**  | 12x faster  |
| 5K    | 100    | 3.0ms      | 247ms    | **250ms** | 25x faster  |
| 10K   | 100    | 7.5ms      | 945ms    | **952ms** | 27x faster  |
| 20K   | 100    | 13ms       | 3.7s     | **3.7s**  | 25x faster  |

### Why All-to-All Is Still Slow

With all-to-all policies, each peer has ~N firewall rules (one per visible
peer per policy direction). Materializing N `FirewallRule` structs per peer ×
N peers = N² total allocations. At 20K peers, that's 400M+ `FirewallRule`
objects per update cycle, creating ~40GB of transient allocations and massive
GC pressure.

This is a fundamental limit of the current NetworkMap data model which
represents firewall rules as individual per-peer objects.

## Correctness Verification

All optimizations are validated against the legacy implementation using 31+
test scenarios that compare network map output field-by-field:

### Test Scenarios

| Category | Scenarios |
|----------|-----------|
| Groups & Policies | Simple bidirectional, all-peers, overlapping groups, many groups (20+) |
| Protocols | TCP, UDP, ICMP, ALL, mixed, port ranges, SSH |
| Policy Features | Unidirectional, drop actions, disabled policies/rules |
| Network Resources | Multiple resources, multiple routers, peer-resource policies |
| Routes | HA routes (same prefix), disabled routes, access control groups |
| DNS | Multiple nameserver groups, disabled management groups, custom zones |
| Peer State | Expired peers, inactivity expiration, validated peer exclusion |
| Scale | 500 peers × 50 groups, isolated peers |

### Test Structure

```
TestNetworkMapCorrectness_LegacyVsCompacted    (31 scenarios)
TestNetworkMapCorrectness_PrecomputedVsLegacy  (19 scenarios)
TestNetworkMapCorrectness_FieldValues          (field-level validation)
TestNetworkMapCorrectness_ExpiredPeersIsolation
TestNetworkMapCorrectness_JSONSnapshot         (byte-level comparison)
TestNetworkMapCorrectness_AllPeersConsistency  (every peer in account)
```

## Performance Summary

Starting from 92.4 seconds for 20K peers:

| Approach | 20K Segmented | 20K All-to-All | Improvement |
|----------|---------------|----------------|-------------|
| Baseline (compacted) | ~92s | ~92s | — |
| + Reverse index | ~29.5s | ~29.5s | 3.1x |
| + Pre-computed groups | **827ms** | **3.7s** | **112x / 25x** |

## Remaining Bottleneck

The all-to-all case is bounded by firewall rule materialization. To improve
further, the architecture would need to:

1. **Lazy serialization**: instead of creating `FirewallRule` structs, write
   directly to the protobuf wire format during gRPC response serialization
2. **Group-level firewall rules**: change the NetworkMap protocol to support
   "allow group X" instead of individual per-peer rules
3. **Delta updates**: send only changes since the last sync rather than the
   full NetworkMap

These require changes to the client-server protocol and are out of scope for
this optimization pass.

## File Reference

| File | Description |
|------|-------------|
| `management/server/types/precomputed_networkmap.go` | Pre-computed group-level approach |
| `management/server/types/account.go` | `BuildPeerGroupsIndex`, `GetPeerGroupsFromIndex` |
| `management/server/types/account_components.go` | Optimized `getPeersGroupsPoliciesRoutes` |
| `management/server/types/networkmap_components.go` | Optimized `GetPeerGroups`, `IsPeerInGroup` |
| `management/server/networkmap_benchmark_test.go` | Benchmark suite |
| `management/server/networkmap_correctness_test.go` | Correctness test suite |
| `management/internals/controllers/network_map/controller/controller.go` | Index passed to controller |
