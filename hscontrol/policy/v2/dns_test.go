package v2

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// TestNodeDNSConfig exercises the basic lookup paths: tier precedence
// (tag > user > group), list-order precedence within a tier, the
// default-as-first-profile rule, and the exemption mechanism (users on
// the default override later profiles' group assignments).
func TestNodeDNSConfig(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "friend", Email: "friend@headscale.net"},
		{Model: gorm.Model{ID: 3}, Name: "boss", Email: "boss@headscale.net"},
		{Model: gorm.Model{ID: 4}, Name: "exempt", Email: "exempt@headscale.net"},
	}
	adminUser, friendUser, bossUser, exemptUser := users[0], users[1], users[2], users[3]

	splitRoutes := map[string][]*dnstype.Resolver{
		"scoresby.cloud": {{Addr: "192.168.4.2"}},
	}
	base := &tailcfg.DNSConfig{
		Routes:  splitRoutes,
		Domains: []string{"ts.scoresby.cloud"},
		Proxied: true,
	}

	// Profiles in list order:
	//   [0] default — used for non-matched nodes; lists exempt@ as a Users
	//       exemption (overrides later profiles' group assignments by tier
	//       precedence: user > group).
	//   [1] admin override — Resolvers, override=true. Both group:admin
	//       and friend@ (user-tier) point at it. friend is also in
	//       group:friend listed later, but user tier beats group tier so
	//       this profile wins for friend.
	//   [2] friend group override — used only by group:friend members
	//       that aren't overridden via user tier above.
	//   [3] server tag — for tagged nodes.
	pol := `{
		"groups": {
			"group:admin": ["admin@", "exempt@"],
			"group:friend": ["friend@", "boss@"]
		},
		"tagOwners": {
			"tag:server": ["admin@"]
		},
		"dns": [
			{
				"nameservers": ["9.9.9.9"],
				"users": ["exempt@"]
			},
			{
				"nameservers": ["192.168.4.2"],
				"overrideLocalDNS": true,
				"groups": ["group:admin"],
				"users": ["friend@"]
			},
			{
				"nameservers": ["1.1.1.1"],
				"groups": ["group:friend"]
			},
			{
				"nameservers": ["10.0.0.1"],
				"overrideLocalDNS": true,
				"tags": ["tag:server"]
			}
		]
	}`

	adminNode := node("admin-phone", "100.64.0.1", "fd7a:115c:a1e0::1", adminUser)
	adminNode.ID = 1
	friendNode := node("friend-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", friendUser)
	friendNode.ID = 2
	bossNode := node("boss-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", bossUser)
	bossNode.ID = 3
	exemptNode := node("exempt-phone", "100.64.0.4", "fd7a:115c:a1e0::4", exemptUser)
	exemptNode.ID = 4
	taggedNode := node("server-1", "100.64.0.5", "fd7a:115c:a1e0::5", types.User{})
	taggedNode.ID = 5
	taggedNode.Tags = types.Strings{"tag:server"}
	untaggedNode := node("other-router", "100.64.0.6", "fd7a:115c:a1e0::6", types.User{})
	untaggedNode.ID = 6
	untaggedNode.Tags = types.Strings{"tag:unrelated"}

	nodes := types.Nodes{adminNode, friendNode, bossNode, exemptNode, taggedNode, untaggedNode}
	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name string
		node types.NodeView
		want *tailcfg.DNSConfig
	}{
		{
			// Admin is in group:admin → profile [1], override=true → Resolvers.
			name: "group-tier-admin",
			node: adminNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:    splitRoutes,
				Domains:   []string{"ts.scoresby.cloud"},
				Proxied:   true,
				Resolvers: []*dnstype.Resolver{{Addr: "192.168.4.2"}},
			},
		},
		{
			// friend@ matches profile [1]'s Users (user tier > group tier);
			// would otherwise match profile [2] via group:friend.
			name: "user-tier-beats-group-tier",
			node: friendNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:    splitRoutes,
				Domains:   []string{"ts.scoresby.cloud"},
				Proxied:   true,
				Resolvers: []*dnstype.Resolver{{Addr: "192.168.4.2"}},
			},
		},
		{
			// boss@ is in group:friend only → profile [2], override=false → FallbackResolvers.
			name: "group-tier-fallback-only",
			node: bossNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:            splitRoutes,
				Domains:           []string{"ts.scoresby.cloud"},
				Proxied:           true,
				FallbackResolvers: []*dnstype.Resolver{{Addr: "1.1.1.1"}},
			},
		},
		{
			// exempt@ is in group:admin (profile [1]) but listed on profile
			// [0]'s Users → user tier matches default first → default wins.
			name: "default-users-exemption-beats-group-assignment",
			node: exemptNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:            splitRoutes,
				Domains:           []string{"ts.scoresby.cloud"},
				Proxied:           true,
				FallbackResolvers: []*dnstype.Resolver{{Addr: "9.9.9.9"}},
			},
		},
		{
			// Tagged node matches profile [3] via tag:server.
			name: "tag-tier",
			node: taggedNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:    splitRoutes,
				Domains:   []string{"ts.scoresby.cloud"},
				Proxied:   true,
				Resolvers: []*dnstype.Resolver{{Addr: "10.0.0.1"}},
			},
		},
		{
			// Tagged node with no matching tag → falls through to the
			// default profile (same as untagged-no-match). The default has
			// nameservers=["9.9.9.9"] with override=false → goes into
			// FallbackResolvers.
			name: "tagged-no-match-uses-default",
			node: untaggedNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:            splitRoutes,
				Domains:           []string{"ts.scoresby.cloud"},
				Proxied:           true,
				FallbackResolvers: []*dnstype.Resolver{{Addr: "9.9.9.9"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pm.NodeDNSConfig(tt.node, base, "")
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("NodeDNSConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNodeDNSConfigListOrderWithinTier verifies that within the group
// tier, the first profile to list a matching group wins — even if the
// node's user is in multiple groups assigned to different profiles.
func TestNodeDNSConfigListOrderWithinTier(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	user := users[0]

	// Default profile [0], then profile [1] for group:first, then profile
	// [2] for group:second. The user is in both groups; list order ⇒
	// profile [1] wins.
	pol := `{
		"groups": {
			"group:first":  ["u@"],
			"group:second": ["u@"]
		},
		"dns": [
			{ "nameservers": ["9.9.9.9"] },
			{ "nameservers": ["1.1.1.1"], "overrideLocalDNS": true, "groups": ["group:first"] },
			{ "nameservers": ["8.8.8.8"], "overrideLocalDNS": true, "groups": ["group:second"] }
		]
	}`

	n := node("u-node", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	got := pm.NodeDNSConfig(n.View(), &tailcfg.DNSConfig{}, "")
	require.NotNil(t, got)
	want := []*dnstype.Resolver{{Addr: "1.1.1.1"}}
	if diff := cmp.Diff(want, got.Resolvers); diff != "" {
		t.Errorf("list-order should pick profile[1] (group:first); mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigDefaultProfileForUnmatched: an untagged node whose
// user matches no assignment list falls through to the first profile.
func TestNodeDNSConfigDefaultProfileForUnmatched(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"},
	}
	user := users[0]

	pol := `{
		"groups": { "group:matters": ["other@"] },
		"dns": [
			{ "nameservers": ["9.9.9.9"] },
			{ "nameservers": ["1.1.1.1"], "groups": ["group:matters"] }
		]
	}`
	n := node("u-node", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	got := pm.NodeDNSConfig(n.View(), &tailcfg.DNSConfig{}, "")
	require.NotNil(t, got)
	want := []*dnstype.Resolver{{Addr: "9.9.9.9"}}
	if diff := cmp.Diff(want, got.FallbackResolvers); diff != "" {
		t.Errorf("expected default (FallbackResolvers since override=false), got mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigMultiTagProfileOrderWins: when a tagged node has
// multiple tags each assigned to different profiles, the profile listed
// first in the policy's dns block wins — regardless of the order the
// tags happen to appear on the node. This keeps the precedence rule
// symmetric across all tiers (profile-list order is the universal
// "within a tier, first wins" mechanism).
func TestNodeDNSConfigMultiTagProfileOrderWins(t *testing.T) {
	pol := `{
		"tagOwners": {
			"tag:aaa": ["owner@"],
			"tag:zzz": ["owner@"]
		},
		"dns": [
			{ "nameservers": ["9.9.9.9"] },
			{ "nameservers": ["1.1.1.1"], "overrideLocalDNS": true, "tags": ["tag:aaa"] },
			{ "nameservers": ["8.8.8.8"], "overrideLocalDNS": true, "tags": ["tag:zzz"] }
		]
	}`
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "owner", Email: "owner@headscale.net"}}
	// Node carries both tags. Profile [1] (tag:aaa) is listed before
	// profile [2] (tag:zzz), so profile [1] should win regardless of the
	// node's internal tag order.
	n := node("server", "100.64.0.1", "fd7a:115c:a1e0::1", types.User{})
	n.ID = 1
	n.Tags = types.Strings{"tag:zzz", "tag:aaa"}

	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	got := pm.NodeDNSConfig(n.View(), &tailcfg.DNSConfig{}, "")
	require.NotNil(t, got)
	want := []*dnstype.Resolver{{Addr: "1.1.1.1"}}
	if diff := cmp.Diff(want, got.Resolvers); diff != "" {
		t.Errorf("profile [1] (tag:aaa) is listed first and must win even though node tag order has tag:zzz first; mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigUntaggedNoValidUser: an untagged node whose user is
// invalid (no user record attached) falls through to the default profile,
// consistent with how unmatched untagged nodes are handled.
func TestNodeDNSConfigUntaggedNoValidUser(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	pol := `{
		"dns": [
			{ "nameservers": ["9.9.9.9"] }
		]
	}`
	// Untagged node with no user attached.
	n := node("orphan", "100.64.0.1", "fd7a:115c:a1e0::1", types.User{})
	n.ID = 1

	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	got := pm.NodeDNSConfig(n.View(), &tailcfg.DNSConfig{}, "")
	require.NotNil(t, got)
	want := []*dnstype.Resolver{{Addr: "9.9.9.9"}}
	if diff := cmp.Diff(want, got.FallbackResolvers); diff != "" {
		t.Errorf("untagged user-less node should get default profile; mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigChainInheritance: when an override profile omits a
// field, it inherits from the default profile (not from base directly).
func TestNodeDNSConfigChainInheritance(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@headscale.net"}}
	user := users[0]

	// Default sets split + searchDomains; admin override sets only
	// nameservers. Admin should inherit split + searchDomains from default.
	pol := `{
		"groups": { "group:admin": ["admin@"] },
		"dns": [
			{
				"split": { "default.example": ["10.0.0.99"] },
				"searchDomains": ["default-search"]
			},
			{
				"nameservers": ["192.168.4.2"],
				"overrideLocalDNS": true,
				"groups": ["group:admin"]
			}
		]
	}`
	n := node("admin-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	base := &tailcfg.DNSConfig{Domains: []string{"ts.example"}}
	got := pm.NodeDNSConfig(n.View(), base, "ts.example")
	require.NotNil(t, got)

	// Resolvers from admin profile
	if got.Resolvers == nil || got.Resolvers[0].Addr != "192.168.4.2" {
		t.Errorf("Resolvers should come from admin override; got %v", got.Resolvers)
	}
	// Routes inherited from default
	want := map[string][]*dnstype.Resolver{"default.example": {{Addr: "10.0.0.99"}}}
	if diff := cmp.Diff(want, got.Routes); diff != "" {
		t.Errorf("admin should inherit Routes from default; mismatch (-want +got):\n%s", diff)
	}
	// Domains: base_domain preserved + searchDomains from default
	wantDomains := []string{"ts.example", "default-search"}
	if diff := cmp.Diff(wantDomains, got.Domains); diff != "" {
		t.Errorf("admin should inherit SearchDomains from default; mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigChainExplicitOverride: when an override profile
// present-empty's a field, it clears (doesn't inherit) from default.
func TestNodeDNSConfigChainExplicitOverride(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@headscale.net"}}
	user := users[0]

	// Default has split; admin override sets split: {} explicitly to
	// clear. Admin's Routes should be empty, NOT inherited.
	pol := `{
		"groups": { "group:admin": ["admin@"] },
		"dns": [
			{ "split": { "default.example": ["10.0.0.99"] } },
			{
				"nameservers": ["192.168.4.2"],
				"overrideLocalDNS": true,
				"split": {},
				"groups": ["group:admin"]
			}
		]
	}`
	n := node("admin-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	got := pm.NodeDNSConfig(n.View(), &tailcfg.DNSConfig{}, "")
	require.NotNil(t, got)

	if len(got.Routes) != 0 {
		t.Errorf("admin's explicit empty split should clear Routes; got %v", got.Routes)
	}
}

// TestNodeDNSConfigEmptyDNSPolicy: with no dns block, every node gets
// base unchanged (full backwards compat for operators using the legacy
// headscale.yaml dns block).
func TestNodeDNSConfigEmptyDNSPolicy(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	user := users[0]
	pol := `{ "groups": { "group:any": ["u@"] } }`

	n := node("u-node", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1

	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	base := &tailcfg.DNSConfig{Domains: []string{"example.net"}, Proxied: true}
	got := pm.NodeDNSConfig(n.View(), base, "")
	if diff := cmp.Diff(base, got); diff != "" {
		t.Errorf("empty dns policy should return base clone (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigNilBase: nil base produces nil result.
func TestNodeDNSConfigNilBase(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	pm, err := NewPolicyManager([]byte(`{}`), users, types.Nodes{}.ViewSlice())
	require.NoError(t, err)
	if got := pm.NodeDNSConfig(types.NodeView{}, nil, ""); got != nil {
		t.Errorf("nil base should produce nil result, got: %+v", got)
	}
}

// TestNodeDNSConfigSplitAndSearchDomains: a profile can override Split
// (Routes) and append SearchDomains to base.Domains.
func TestNodeDNSConfigSplitAndSearchDomains(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "eng", Email: "eng@headscale.net"}}
	user := users[0]

	pol := `{
		"groups": { "group:eng": ["eng@"] },
		"dns": [
			{ "nameservers": ["9.9.9.9"] },
			{
				"nameservers": ["192.168.4.2"],
				"overrideLocalDNS": true,
				"split": { "internal.example": ["10.0.0.1"] },
				"searchDomains": ["internal.example"],
				"groups": ["group:eng"]
			}
		]
	}`
	n := node("eng-laptop", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	base := &tailcfg.DNSConfig{
		Routes:  map[string][]*dnstype.Resolver{"scoresby.cloud": {{Addr: "192.168.4.99"}}},
		Domains: []string{"ts.scoresby.cloud"},
	}
	got := pm.NodeDNSConfig(n.View(), base, "ts.scoresby.cloud")
	require.NotNil(t, got)

	// Resolvers should be the profile's nameservers
	wantRes := []*dnstype.Resolver{{Addr: "192.168.4.2"}}
	if diff := cmp.Diff(wantRes, got.Resolvers); diff != "" {
		t.Errorf("Resolvers mismatch (-want +got):\n%s", diff)
	}
	// Routes should be REPLACED by Split (not merged)
	wantRoutes := map[string][]*dnstype.Resolver{"internal.example": {{Addr: "10.0.0.1"}}}
	if diff := cmp.Diff(wantRoutes, got.Routes); diff != "" {
		t.Errorf("Routes should be replaced by Split; mismatch (-want +got):\n%s", diff)
	}
	// Domains should have searchDomains APPENDED
	wantDomains := []string{"ts.scoresby.cloud", "internal.example"}
	if diff := cmp.Diff(wantDomains, got.Domains); diff != "" {
		t.Errorf("Domains should append searchDomains; mismatch (-want +got):\n%s", diff)
	}
}

// ---- Validation tests ----

// TestSetPolicyRejectsDNSConflictOnReload: when yamlDNSPresent has been
// recorded as true, a hot-reload that introduces a policy.dns block is
// rejected and the in-memory policy is left untouched.
func TestSetPolicyRejectsDNSConflictOnReload(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	// Initial policy has no dns block — startup-time check would have
	// passed, so we set yamlDNSPresent=true to simulate yaml.dns being
	// configured.
	pol := `{ "groups": { "group:any": ["u@"] } }`
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
	require.NoError(t, err)
	pm.SetYAMLDNSPresent(true)

	// Snapshot the original DNS state for later comparison.
	if pm.HasDNSConfig() {
		t.Fatal("initial policy should have no DNS block")
	}

	// Operator edits the policy file in-place to add a dns block.
	conflictingPol := `{
		"groups": { "group:any": ["u@"] },
		"dns": [
			{ "nameservers": ["1.1.1.1"] }
		]
	}`
	changed, err := pm.SetPolicy([]byte(conflictingPol))
	if err == nil {
		t.Fatal("expected SetPolicy to reject DNS conflict, got nil")
	}
	if !strings.Contains(err.Error(), "policy.dns conflicts") {
		t.Errorf("expected error to mention conflict, got: %v", err)
	}
	if changed {
		t.Error("SetPolicy should not report changed=true when rejecting")
	}
	// In-memory policy should still be the original.
	if pm.HasDNSConfig() {
		t.Error("policy should remain unchanged after rejected reload")
	}
}

// TestSetPolicyAllowsDNSReloadWhenYAMLEmpty: when yamlDNSPresent is
// false, a reload that introduces a policy.dns block is accepted.
func TestSetPolicyAllowsDNSReloadWhenYAMLEmpty(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	pol := `{ "groups": { "group:any": ["u@"] } }`
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
	require.NoError(t, err)
	// yamlDNSPresent defaults to false (no SetYAMLDNSPresent call).

	newPol := `{
		"groups": { "group:any": ["u@"] },
		"dns": [
			{ "nameservers": ["1.1.1.1"] }
		]
	}`
	_, err = pm.SetPolicy([]byte(newPol))
	require.NoError(t, err)
	if !pm.HasDNSConfig() {
		t.Error("policy should now have a DNS block")
	}
}

// TestPolicyValidateDNSDefaultProfileGroupsForbidden: the first profile
// (default) cannot have a Groups list.
func TestPolicyValidateDNSDefaultProfileGroupsForbidden(t *testing.T) {
	pol := `{
		"groups": { "group:x": ["u@"] },
		"dns": [
			{ "nameservers": ["9.9.9.9"], "groups": ["group:x"] }
		]
	}`
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	_, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
	if err == nil {
		t.Fatal("expected validation error for groups on default profile")
	}
	if !errors.Is(err, ErrDNSDefaultProfileHasGroups) {
		t.Errorf("expected ErrDNSDefaultProfileHasGroups, got: %v", err)
	}
}

// TestPolicyValidateDNSProfileHasNoBody: a non-default profile with
// assignment lists but no DNS body fields (nameservers / split /
// searchDomains) is a no-op against the default and almost certainly an
// operator misconfiguration. Validation should reject it.
func TestPolicyValidateDNSProfileHasNoBody(t *testing.T) {
	pol := `{
		"groups": { "group:x": ["u@"] },
		"dns": [
			{ "nameservers": ["9.9.9.9"] },
			{ "groups": ["group:x"] }
		]
	}`
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	_, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
	if err == nil {
		t.Fatal("expected validation error for profile with no DNS body fields, got nil")
	}
	if !errors.Is(err, ErrDNSProfileHasNoBody) {
		t.Errorf("expected ErrDNSProfileHasNoBody, got: %v", err)
	}
}

// TestPolicyValidateDNSDefaultProfileBodyOptional: the default profile
// (index 0) is exempt from the "must have a body" rule — an empty
// default just means "no DNS overrides at all" which is allowed if the
// operator opts into the dns block to add later profiles.
func TestPolicyValidateDNSDefaultProfileBodyOptional(t *testing.T) {
	pol := `{
		"groups": { "group:x": ["u@"] },
		"dns": [
			{},
			{ "nameservers": ["9.9.9.9"], "groups": ["group:x"] }
		]
	}`
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	if _, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice()); err != nil {
		t.Errorf("empty default profile should be allowed; got: %v", err)
	}
}

// TestPolicyValidateDNSDuplicatePrincipal: a group / user / tag may
// appear in at most one profile's assignment list.
func TestPolicyValidateDNSDuplicatePrincipal(t *testing.T) {
	cases := map[string]string{
		"group-in-two-profiles": `{
			"groups": { "group:x": ["u@"] },
			"dns": [
				{ "nameservers": ["9.9.9.9"] },
				{ "nameservers": ["1.1.1.1"], "groups": ["group:x"] },
				{ "nameservers": ["8.8.8.8"], "groups": ["group:x"] }
			]
		}`,
		"user-in-two-profiles": `{
			"dns": [
				{ "nameservers": ["9.9.9.9"], "users": ["u@"] },
				{ "nameservers": ["1.1.1.1"], "users": ["u@"] }
			]
		}`,
		"tag-in-two-profiles": `{
			"tagOwners": { "tag:t": ["u@"] },
			"dns": [
				{ "nameservers": ["9.9.9.9"] },
				{ "nameservers": ["1.1.1.1"], "tags": ["tag:t"] },
				{ "nameservers": ["8.8.8.8"], "tags": ["tag:t"] }
			]
		}`,
	}
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	for name, pol := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
			if err == nil {
				t.Fatal("expected validation error for duplicate principal across profiles, got nil")
			}
			if !errors.Is(err, ErrDNSPrincipalAssignedTwice) {
				t.Errorf("expected ErrDNSPrincipalAssignedTwice, got: %v", err)
			}
		})
	}
}

// TestPolicyValidateDNSUndefinedReference: every referenced group must
// exist in the policy's top-level groups; every tag must exist in
// tagOwners; every username must be syntactically valid.
func TestPolicyValidateDNSUndefinedReference(t *testing.T) {
	cases := map[string]string{
		"undefined-group": `{
			"groups": { "group:defined": ["u@"] },
			"dns": [
				{ "nameservers": ["9.9.9.9"] },
				{ "nameservers": ["1.1.1.1"], "groups": ["group:undefined"] }
			]
		}`,
		"undefined-tag": `{
			"tagOwners": { "tag:known": ["u@"] },
			"dns": [
				{ "nameservers": ["9.9.9.9"] },
				{ "nameservers": ["1.1.1.1"], "tags": ["tag:unknown"] }
			]
		}`,
		"invalid-username": `{
			"dns": [
				{ "nameservers": ["9.9.9.9"], "users": ["no-at-sign"] }
			]
		}`,
	}
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	for name, pol := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
			if err == nil {
				t.Fatal("expected validation error for undefined reference, got nil")
			}
		})
	}
}

// ---- applyDNSProfile direct unit tests ----

func TestApplyDNSProfileFieldHandoff(t *testing.T) {
	base := &tailcfg.DNSConfig{
		Resolvers:         []*dnstype.Resolver{{Addr: "base-res"}},
		FallbackResolvers: []*dnstype.Resolver{{Addr: "base-fb"}},
		Routes:            map[string][]*dnstype.Resolver{"old.example": {{Addr: "old-res"}}},
		Domains:           []string{"base.example"},
	}

	nsList := func(s ...string) *[]string { x := []string(s); return &x }
	splitMap := func(m map[string][]string) *map[string][]string { return &m }

	t.Run("override-true-clears-fallback", func(t *testing.T) {
		got := applyDNSProfile(base, DNSProfile{
			Nameservers:      nsList("1.1.1.1"),
			OverrideLocalDNS: true,
		}, "base.example")
		if got.Resolvers[0].Addr != "1.1.1.1" {
			t.Errorf("Resolvers should be set to profile.Nameservers")
		}
		if got.FallbackResolvers != nil {
			t.Errorf("FallbackResolvers should be cleared when override=true; got %v", got.FallbackResolvers)
		}
	})

	t.Run("override-false-clears-resolvers", func(t *testing.T) {
		got := applyDNSProfile(base, DNSProfile{
			Nameservers:      nsList("8.8.8.8"),
			OverrideLocalDNS: false,
		}, "base.example")
		if got.FallbackResolvers[0].Addr != "8.8.8.8" {
			t.Errorf("FallbackResolvers should be set to profile.Nameservers")
		}
		if got.Resolvers != nil {
			t.Errorf("Resolvers should be cleared when override=false; got %v", got.Resolvers)
		}
	})

	t.Run("absent-nameservers-inherits-both", func(t *testing.T) {
		got := applyDNSProfile(base, DNSProfile{}, "base.example")
		if diff := cmp.Diff(base.Resolvers, got.Resolvers); diff != "" {
			t.Errorf("absent nameservers should leave Resolvers inherited; mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(base.FallbackResolvers, got.FallbackResolvers); diff != "" {
			t.Errorf("absent nameservers should leave FallbackResolvers inherited; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("present-empty-nameservers-clears-both", func(t *testing.T) {
		// Present-but-empty replaces; admin sets Nameservers: &[]string{} to
		// explicitly clear both Resolvers and FallbackResolvers.
		got := applyDNSProfile(base, DNSProfile{
			Nameservers:      nsList(),
			OverrideLocalDNS: true,
		}, "base.example")
		if got.Resolvers != nil {
			t.Errorf("present-empty Nameservers with override=true should clear Resolvers; got %v", got.Resolvers)
		}
		if got.FallbackResolvers != nil {
			t.Errorf("FallbackResolvers should be cleared; got %v", got.FallbackResolvers)
		}
	})

	t.Run("split-replaces-routes", func(t *testing.T) {
		got := applyDNSProfile(base, DNSProfile{
			Split: splitMap(map[string][]string{"new.example": {"new-res"}}),
		}, "base.example")
		want := map[string][]*dnstype.Resolver{"new.example": {{Addr: "new-res"}}}
		if diff := cmp.Diff(want, got.Routes); diff != "" {
			t.Errorf("Split should replace Routes; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("absent-split-inherits-routes", func(t *testing.T) {
		got := applyDNSProfile(base, DNSProfile{}, "base.example")
		if diff := cmp.Diff(base.Routes, got.Routes); diff != "" {
			t.Errorf("absent Split should leave Routes inherited; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("present-empty-split-clears-routes", func(t *testing.T) {
		got := applyDNSProfile(base, DNSProfile{
			Split: splitMap(map[string][]string{}),
		}, "base.example")
		if len(got.Routes) != 0 {
			t.Errorf("present-empty Split should clear Routes; got %v", got.Routes)
		}
	})

	t.Run("search-domains-replaces-preserving-base-domain", func(t *testing.T) {
		// base.Domains is ["base.example"]. Profile sets searchDomains
		// ["new.example"]. Result: ["base.example", "new.example"] —
		// base_domain (Domains[0]) preserved, search-domain portion replaced.
		got := applyDNSProfile(base, DNSProfile{
			SearchDomains: &[]string{"new.example"},
		}, "base.example")
		want := []string{"base.example", "new.example"}
		if diff := cmp.Diff(want, got.Domains); diff != "" {
			t.Errorf("SearchDomains should replace Domains[1:] preserving Domains[0]; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("search-domains-no-base-domain-replaces-whole-slice", func(t *testing.T) {
		// MagicDNS off: baseDomain is empty and base.Domains is entirely
		// search suffixes. A profile's SearchDomains should replace the
		// whole slice — NOT preserve Domains[0] as if it were base_domain
		// (that would silently keep an inherited search suffix the
		// operator thought they were replacing).
		searchOnlyBase := &tailcfg.DNSConfig{
			Domains: []string{"inherited-search.example", "another-search.example"},
		}
		got := applyDNSProfile(searchOnlyBase, DNSProfile{
			SearchDomains: &[]string{"new.example"},
		}, "")
		want := []string{"new.example"}
		if diff := cmp.Diff(want, got.Domains); diff != "" {
			t.Errorf("SearchDomains with no baseDomain should replace whole Domains; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("empty-search-domains-leaves-domains-untouched", func(t *testing.T) {
		got := applyDNSProfile(base, DNSProfile{}, "base.example")
		if diff := cmp.Diff(base.Domains, got.Domains); diff != "" {
			t.Errorf("empty SearchDomains should leave Domains untouched; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("fully-empty-profile-equals-base", func(t *testing.T) {
		got := applyDNSProfile(base, DNSProfile{}, "base.example")
		if diff := cmp.Diff(base, got); diff != "" {
			t.Errorf("a fully-empty profile should produce base.Clone(); mismatch (-want +got):\n%s", diff)
		}
	})
}
