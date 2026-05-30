package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestResolveMagicDNS(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("magicdns"))
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	// Poor mans cache
	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	_, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	for _, client := range allClients {
		for _, peer := range allClients {
			// It is safe to ignore this error as we handled it when caching it
			peerFQDN, _ := peer.FQDN()

			assert.Equal(t, peer.Hostname()+".headscale.net.", peerFQDN)

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				command := []string{
					"tailscale",
					"ip", peerFQDN,
				}
				result, _, err := client.Execute(command)
				assert.NoError(ct, err, "Failed to execute resolve/ip command %s from %s", peerFQDN, client.Hostname())

				ips, err := peer.IPs()
				assert.NoError(ct, err, "Failed to get IPs for %s", peer.Hostname())

				for _, ip := range ips {
					assert.Contains(ct, result, ip.String(), "IP %s should be found in DNS resolution result from %s to %s", ip.String(), client.Hostname(), peer.Hostname())
				}
			}, integrationutil.StatusReadyTimeout, 2*time.Second)
		}
	}
}

func TestResolveMagicDNSExtraRecordsPath(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	const erPath = "/tmp/extra_records.json"

	extraRecords := make([]tailcfg.DNSRecord, 0, 2)
	extraRecords = append(extraRecords, tailcfg.DNSRecord{
		Name:  "test.myvpn.example.com",
		Type:  "A",
		Value: "6.6.6.6",
	})
	b, _ := json.Marshal(extraRecords) //nolint:errchkjson

	err = scenario.CreateHeadscaleEnv([]tsic.Option{
		tsic.WithPackages("python3", "curl", "bind-tools"),
	},
		hsic.WithTestName("extrarecords"),
		hsic.WithConfigEnv(map[string]string{
			// Disable global nameservers to make the test run offline.
			"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "",
			"HEADSCALE_DNS_EXTRA_RECORDS_PATH": erPath,
		}),
		hsic.WithFileInContainer(erPath, b),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	// Poor mans cache
	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	_, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "test.myvpn.example.com"}, "6.6.6.6")
	}

	hs, err := scenario.Headscale()
	require.NoError(t, err)

	// Write the file directly into place from the docker API.
	b0, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
		{
			Name:  "docker.myvpn.example.com",
			Type:  "A",
			Value: "2.2.2.2",
		},
	})

	err = hs.WriteFile(erPath, b0)
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "docker.myvpn.example.com"}, "2.2.2.2")
	}

	// Write a new file and move it to the path to ensure the reload
	// works when a file is moved atomically into place.
	extraRecords = append(extraRecords, tailcfg.DNSRecord{
		Name:  "otherrecord.myvpn.example.com",
		Type:  "A",
		Value: "7.7.7.7",
	})
	b2, _ := json.Marshal(extraRecords) //nolint:errchkjson

	err = hs.WriteFile(erPath+"2", b2)
	require.NoError(t, err)
	_, err = hs.Execute([]string{"mv", erPath + "2", erPath})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "test.myvpn.example.com"}, "6.6.6.6")
		assertCommandOutputContains(t, client, []string{"dig", "otherrecord.myvpn.example.com"}, "7.7.7.7")
	}

	// Write a new file and copy it to the path to ensure the reload
	// works when a file is copied into place.
	b3, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
		{
			Name:  "copy.myvpn.example.com",
			Type:  "A",
			Value: "8.8.8.8",
		},
	})

	err = hs.WriteFile(erPath+"3", b3)
	require.NoError(t, err)
	_, err = hs.Execute([]string{"cp", erPath + "3", erPath})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "copy.myvpn.example.com"}, "8.8.8.8")
	}

	// Write in place to ensure pipe like behaviour works
	b4, _ := json.Marshal([]tailcfg.DNSRecord{ //nolint:errchkjson
		{
			Name:  "docker.myvpn.example.com",
			Type:  "A",
			Value: "9.9.9.9",
		},
	})
	command := []string{"echo", fmt.Sprintf("'%s'", string(b4)), ">", erPath}
	_, err = hs.Execute([]string{"bash", "-c", strings.Join(command, " ")})
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "docker.myvpn.example.com"}, "9.9.9.9")
	}

	// Delete the file and create a new one to ensure it is picked up again.
	_, err = hs.Execute([]string{"rm", erPath})
	require.NoError(t, err)

	// The same paths should still be available as it is not cleared on delete.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		for _, client := range allClients {
			result, _, err := client.Execute([]string{"dig", "docker.myvpn.example.com"})
			assert.NoError(ct, err)
			assert.Contains(ct, result, "9.9.9.9")
		}
	}, integrationutil.ScaledTimeout(10*time.Second), 1*time.Second)

	// Write a new file, the backoff mechanism should make the filewatcher pick it up
	// again.
	err = hs.WriteFile(erPath, b3)
	require.NoError(t, err)

	for _, client := range allClients {
		assertCommandOutputContains(t, client, []string{"dig", "copy.myvpn.example.com"}, "8.8.8.8")
	}
}

// TestPolicyDNSProfiles exercises the policy DNS profiles feature
// end-to-end across two configurations and a hot-reload between them:
//
//	Phase 1 (default-only policy): the policy has a single default
//	profile that sets split DNS for an internal domain. Both the admin
//	and guest clients should receive that split DNS and nothing else
//	(no Resolvers, no FallbackResolvers). This validates the default-
//	profile catch-all path.
//
//	Phase 2 (hot reload → default + override): the policy is swapped
//	in place to add a second profile that overrides Resolvers for
//	group:admin. The filewatcher → SetPolicy path should propagate
//	the new policy without restarting headscale.
//
//	Phase 3 (post-reload chain inheritance): admin's netmap should
//	carry the override Resolvers AND the default profile's Routes
//	(inherited via the base → default → matched chain). Guest's netmap
//	should remain on the default profile alone, demonstrating that
//	non-matched nodes keep the default after the reload.
//
// One scenario setup, three configurations validated: default-only,
// the hot-reload mechanism, and the chained-inheritance result.
func TestPolicyDNSProfiles(t *testing.T) {
	IntegrationSkip(t)

	const (
		adminUser   = "admin-user"
		guestUser   = "guest-user"
		splitDomain = "internal.example"
		splitNS     = "10.99.0.99"
		overrideNS  = "10.99.0.42"
		adminGroup  = "group:admin"
	)

	splitMap := map[string][]string{splitDomain: {splitNS}}

	// Initial policy: just the default profile with split DNS. No
	// override profile yet.
	initialPolicy := &policyv2.Policy{
		Groups: policyv2.Groups{
			policyv2.Group(adminGroup): []policyv2.Username{
				policyv2.Username(adminUser + "@"),
			},
		},
		DNS: policyv2.PolicyDNS{
			{Split: &splitMap},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{adminUser, guestUser},
		Versions:     []string{"head"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{tsic.WithNetfilter("off")},
		hsic.WithACLPolicy(initialPolicy),
		hsic.WithTestName("dnsreload"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DNS_BASE_DOMAIN":        "",
			"HEADSCALE_DNS_MAGIC_DNS":          "false",
			"HEADSCALE_DNS_OVERRIDE_LOCAL_DNS": "false",
			"HEADSCALE_DNS_NAMESERVERS_GLOBAL": "",
			"HEADSCALE_MAGIC_DNS_ENABLED":      "true",
			"HEADSCALE_MAGIC_DNS_BASE_DOMAIN":  "headscale.net",
		}),
	)
	requireNoErrHeadscaleEnv(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	adminClients, err := scenario.ListTailscaleClients(adminUser)
	requireNoErrListClients(t, err)
	require.NotEmpty(t, adminClients)
	guestClients, err := scenario.ListTailscaleClients(guestUser)
	requireNoErrListClients(t, err)
	require.NotEmpty(t, guestClients)

	// Phase 1: under the initial policy, everyone (admin + guest) gets
	// the default profile: split DNS, no Resolvers, no FallbackResolvers.
	assertDefaultOnly := func(stage string) {
		for _, client := range append(adminClients, guestClients...) {
			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				nm, err := client.Netmap()
				if !assert.NoError(ct, err) || !assert.NotNil(ct, nm) || !assert.NotNil(ct, nm.DNS) {
					return
				}
				assert.Empty(ct, nm.DNS.Resolvers, "%s: %s should have no Resolvers under default-only policy", stage, client.Hostname())
				assert.Empty(ct, nm.DNS.FallbackResolvers, "%s: %s should have no FallbackResolvers under default-only policy", stage, client.Hostname())
				if assert.Contains(ct, nm.DNS.Routes, splitDomain, "%s: %s should receive Routes from the default profile", stage, client.Hostname()) {
					assert.Len(ct, nm.DNS.Routes[splitDomain], 1)
					assert.Equal(ct, splitNS, nm.DNS.Routes[splitDomain][0].Addr)
				}
			}, integrationutil.StatusReadyTimeout, 1*time.Second)
		}
	}
	assertDefaultOnly("initial")

	// Phase 2: hot-reload the policy to add a group:admin override.
	overrideNSList := []string{overrideNS}
	updatedPolicy := &policyv2.Policy{
		Groups: initialPolicy.Groups,
		DNS: policyv2.PolicyDNS{
			{Split: &splitMap},
			{
				Nameservers:      &overrideNSList,
				OverrideLocalDNS: true,
				Groups:           []policyv2.Group{policyv2.Group(adminGroup)},
			},
		},
	}

	headscale, err := scenario.Headscale()
	require.NoError(t, err)
	require.NoError(t, headscale.SetPolicy(updatedPolicy),
		"hot-reloading the policy should succeed (no cross-file conflict, no validation rejection)")

	// Phase 3: admin now receives the override Resolvers + inherited Routes;
	// guest still receives the default profile only. EventuallyWithT bounds
	// the wait so the netmap update can propagate to the clients.
	for _, client := range adminClients {
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			nm, err := client.Netmap()
			if !assert.NoError(ct, err) || !assert.NotNil(ct, nm) || !assert.NotNil(ct, nm.DNS) {
				return
			}
			if assert.Len(ct, nm.DNS.Resolvers, 1, "admin should have one Resolver after reload") {
				assert.Equal(ct, overrideNS, nm.DNS.Resolvers[0].Addr,
					"admin's Resolvers should be the override after reload")
			}
			assert.Empty(ct, nm.DNS.FallbackResolvers)
			if assert.Contains(ct, nm.DNS.Routes, splitDomain,
				"admin should still inherit Routes from the default profile") {
				assert.Len(ct, nm.DNS.Routes[splitDomain], 1)
				assert.Equal(ct, splitNS, nm.DNS.Routes[splitDomain][0].Addr)
			}
		}, integrationutil.PolicyPropagationTimeout, 2*time.Second,
			"admin %s should receive override after hot-reload", client.Hostname())
	}
	for _, client := range guestClients {
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			nm, err := client.Netmap()
			if !assert.NoError(ct, err) || !assert.NotNil(ct, nm) || !assert.NotNil(ct, nm.DNS) {
				return
			}
			assert.Empty(ct, nm.DNS.Resolvers, "guest should remain on default profile")
			assert.Empty(ct, nm.DNS.FallbackResolvers)
			assert.Contains(ct, nm.DNS.Routes, splitDomain)
		}, integrationutil.PolicyPropagationTimeout, 2*time.Second,
			"guest %s should remain on default after hot-reload", client.Hostname())
	}
}
