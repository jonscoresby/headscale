package policy

import (
	"net/netip"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

type PolicyManager interface {
	// Filter returns the current filter rules for the entire tailnet and the associated matchers.
	Filter() ([]tailcfg.FilterRule, []matcher.Match)
	// FilterForNode returns filter rules for a specific node, handling autogroup:self
	FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error)
	// MatchersForNode returns matchers for peer relationship determination (unreduced)
	MatchersForNode(node types.NodeView) ([]matcher.Match, error)
	// BuildPeerMap constructs peer relationship maps for the given nodes
	BuildPeerMap(nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeView
	SSHPolicy(baseURL string, node types.NodeView) (*tailcfg.SSHPolicy, error)
	// SSHCheckParams resolves the SSH check period for a (src, dst) pair
	// from the current policy, avoiding trust of client-provided URL params.
	SSHCheckParams(srcNodeID, dstNodeID types.NodeID) (time.Duration, bool)
	// NodeDNSConfig returns the DNSConfig for the given node. The policy's
	// dns block is a list of profiles; the first profile that matches the
	// node by tag, user, or group supplies the node's DNS config (with
	// list-order precedence within each tier and tag > user > group across
	// tiers). Untagged nodes that match no profile fall through to the
	// first profile (the default). With no dns block at all in the policy,
	// base is returned unchanged.
	NodeDNSConfig(node types.NodeView, base *tailcfg.DNSConfig, baseDomain string) *tailcfg.DNSConfig
	// HasDNSConfig reports whether the policy has a non-empty dns block.
	// Used to enforce the cross-file invariant that DNS is configured in
	// at most one of headscale.yaml or the policy file.
	HasDNSConfig() bool
	// SetYAMLDNSPresent records whether headscale.yaml's legacy dns block
	// has any content. Set once at startup; consulted by SetPolicy on
	// hot-reload to keep the cross-file invariant from being violated
	// after server start.
	SetYAMLDNSPresent(present bool)
	SetPolicy(pol []byte) (bool, error)
	SetUsers(users []types.User) (bool, error)
	SetNodes(nodes views.Slice[types.NodeView]) (bool, error)
	// NodeCanHaveTag reports whether the given node can have the given tag.
	NodeCanHaveTag(node types.NodeView, tag string) bool

	// TagExists reports whether the given tag is defined in the policy.
	TagExists(tag string) bool

	// NodeCanApproveRoute reports whether the given node can approve the given route.
	NodeCanApproveRoute(node types.NodeView, route netip.Prefix) bool

	// ViaRoutesForPeer computes via grant effects for a viewer-peer pair.
	// It returns which routes should be included (peer is via-designated for viewer)
	// and excluded (steered to a different peer). When no via grants apply,
	// both fields are empty and the caller falls back to existing behavior.
	ViaRoutesForPeer(viewer, peer types.NodeView) types.ViaRouteResult

	// NodeCapMap returns the policy-derived CapMap for the given node,
	// or nil when no nodeAttrs entry targets it. The returned map is
	// owned by the manager; treat it as read-only and copy before
	// merging into a [tailcfg.Node]. It describes the node's own
	// capabilities, not a per-viewer view.
	NodeCapMap(id types.NodeID) tailcfg.NodeCapMap

	// NodeCapMaps returns a snapshot of the per-node policy CapMap so
	// callers can amortise lock acquisitions over a peer loop. The
	// outer map is a fresh container; the inner [tailcfg.NodeCapMap]
	// values are shared with the manager and read-only.
	NodeCapMaps() map[types.NodeID]tailcfg.NodeCapMap

	// NodesWithChangedCapMap returns the IDs of nodes whose nodeAttrs
	// CapMap shifted during recent updateLocked calls. The buffer
	// drains on read; callers consume it once per update cycle to
	// decide which nodes need a self-targeted MapResponse.
	// refreshNodeAttrsLocked appends to the buffer rather than
	// overwriting, so a SetUsers/SetNodes between SetPolicy and the
	// drain cannot lose the policy-reload diff.
	NodesWithChangedCapMap() []types.NodeID

	Version() int
	DebugString() string
}

// NewPolicyManager returns a new [PolicyManager].
func NewPolicyManager(pol []byte, users []types.User, nodes views.Slice[types.NodeView]) (PolicyManager, error) {
	var (
		polMan PolicyManager
		err    error
	)

	polMan, err = policyv2.NewPolicyManager(pol, users, nodes)
	if err != nil {
		return nil, err
	}

	return polMan, err
}

// PolicyManagersForTest returns all available [PolicyManager] implementations to
// be used in tests to validate them in tests that try to determine that they
// behave the same.
func PolicyManagersForTest(pol []byte, users []types.User, nodes views.Slice[types.NodeView]) ([]PolicyManager, error) {
	var polMans []PolicyManager

	for _, pmf := range PolicyManagerFuncsForTest(pol) {
		pm, err := pmf(users, nodes)
		if err != nil {
			return nil, err
		}

		polMans = append(polMans, pm)
	}

	return polMans, nil
}

func PolicyManagerFuncsForTest(pol []byte) []func([]types.User, views.Slice[types.NodeView]) (PolicyManager, error) {
	polmanFuncs := make([]func([]types.User, views.Slice[types.NodeView]) (PolicyManager, error), 0, 1)

	polmanFuncs = append(polmanFuncs, func(u []types.User, n views.Slice[types.NodeView]) (PolicyManager, error) {
		return policyv2.NewPolicyManager(pol, u, n)
	})

	return polmanFuncs
}
