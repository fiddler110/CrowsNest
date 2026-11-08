package dockerguard

import (
	"fmt"
	"strings"
	"testing"
)

// A scope may pin exact container addresses per network ("ipv4"). Everything
// else about fixed addresses stays refused, as before.

const pinnedScopes = `[{
  "name": "palworld",
  "images": ["thijsvanloef/palworld-server-docker"],
  "binds": ["` + palDir + `"],
  "networks": ["crowsnest-games-net"],
  "ipv4": {"crowsnest-games-net": ["192.168.0.50"]},
  "ports": [{"host_ip": "10.0.0.2", "host_port": "8211", "proto": "udp"}],
  "labels": {"com.centurylinklabs.watchtower.enable": "false"}
}]`

func withAddress(t testing.TB, addr string) map[string]any {
	body := composeBody(t)
	ep := body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["crowsnest-games-net"].(map[string]any)
	ep["IPAMConfig"] = map[string]any{"IPv4Address": addr, "IPv6Address": "", "LinkLocalIPs": nil}
	ep["IPAddress"] = addr // compose repeats a fixed address here (verified against compose v5.7 and Docker 29)
	return body
}

func TestPinnedAddressIsAllowedOnlyWhereTheScopeListsIt(t *testing.T) {
	h := newHarness(t, pinnedScopes)
	if r := h.request("POST", create, withAddress(t, "192.168.0.50")); r.code != 201 {
		t.Fatalf("pinned address refused: %s", r)
	}
	// An empty address (no fixed address) keeps working.
	if r := h.request("POST", create, withAddress(t, "")); r.code != 201 {
		t.Fatalf("no address refused: %s", r)
	}
	h.eng.clear()
	for _, addr := range []string{"192.168.0.51", "192.168.0.5", "10.0.1.16", "0.0.0.0", "192.168.0.50 ", "192.168.000.050", "::1"} {
		h.refused("POST", create, withAddress(t, addr))
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create with an unlisted address")
	}
}

func TestPinnedAddressByNetworkIDIsResolvedToTheName(t *testing.T) {
	h := newHarness(t, pinnedScopes)
	body := composeBody(t, `{"NetworkMode": "NETID"}`)
	body["NetworkingConfig"] = jv(t, `{"EndpointsConfig": {"NETID": {"Aliases": ["palworld"], "IPAMConfig": {"IPv4Address": "192.168.0.50"}}}}`)
	if r := h.request("POST", create, body); r.code != 201 {
		t.Fatalf("pinned address on a network id refused: %s", r)
	}
	h.eng.clear()
	body["NetworkingConfig"] = jv(t, `{"EndpointsConfig": {"NETID": {"Aliases": ["palworld"], "IPAMConfig": {"IPv4Address": "192.168.0.51"}}}}`)
	h.refused("POST", create, body)
}

func TestScopeWithoutAPinStillRefusesAnyFixedAddress(t *testing.T) {
	h := newHarness(t, scopesJSON)
	for _, addr := range []string{"192.168.0.50", "172.30.0.3"} {
		h.refused("POST", create, withAddress(t, addr))
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

func TestBadIPv4PinsStopTheGuardStarting(t *testing.T) {
	scope := func(ipv4 string) string {
		return fmt.Sprintf(`[{"name": "palworld", "images": ["thijsvanloef/palworld-server-docker"], "networks": ["crowsnest-games-net"], "ipv4": %s}]`, ipv4)
	}
	for _, bad := range []string{
		`[]`, `"10.0.1.16"`, `{}`,
		`{"crowsnest-games-net": []}`,
		`{"crowsnest-games-net": "10.0.1.16"}`,
		`{"other-net": ["10.0.1.16"]}`, // not a network the scope may join
		`{"crowsnest-games-net": ["0.0.0.0"]}`,
		`{"crowsnest-games-net": ["127.0.0.1"]}`,
		`{"crowsnest-games-net": ["224.0.0.1"]}`,
		`{"crowsnest-games-net": ["169.254.1.1"]}`,
		`{"crowsnest-games-net": ["255.255.255.255"]}`,
		`{"crowsnest-games-net": ["10.0.1.016"]}`,
		`{"crowsnest-games-net": ["10.0.1.16/24"]}`,
		`{"crowsnest-games-net": [" 10.0.1.16"]}`,
		`{"crowsnest-games-net": ["::1"]}`,
		`{"crowsnest-games-net": ["fe80::1"]}`,
		`{"crowsnest-games-net": [16]}`,
		`{"crowsnest-games-net": [null]}`,
		`{"crowsnest-games-net": [""]}`,
	} {
		if _, err := LoadScopes(scope(bad)); err == nil {
			t.Errorf("ipv4 %s was accepted", bad)
		}
	}
	sc, err := LoadScopes(scope(`{"crowsnest-games-net": ["10.0.1.16", "10.0.1.17"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sc[0].IPv4["crowsnest-games-net"], ","); got != "10.0.1.16,10.0.1.17" {
		t.Errorf("pins = %s", got)
	}
}

// Compose repeats a fixed address in the endpoint's IPAddress field. It follows the
// same pin as IPAMConfig.IPv4Address; the two may not name different things.
func TestIPAddressFieldFollowsThePin(t *testing.T) {
	h := newHarness(t, pinnedScopes)
	ok := composeBody(t)
	ep := ok["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["crowsnest-games-net"].(map[string]any)
	ep["IPAddress"] = "192.168.0.50" // IPAMConfig left empty: the same single address
	if r := h.request("POST", create, ok); r.code != 201 {
		t.Fatalf("pinned IPAddress alone refused: %s", r)
	}
	h.eng.clear()
	for _, tc := range []struct{ ipam, field string }{
		{"192.168.0.50", "192.168.0.51"}, // pinned in IPAMConfig, something else in IPAddress
		{"", "192.168.0.51"},
		{"", "172.30.0.3"},
	} {
		body := composeBody(t)
		e := body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["crowsnest-games-net"].(map[string]any)
		e["IPAMConfig"] = map[string]any{"IPv4Address": tc.ipam, "IPv6Address": "", "LinkLocalIPs": nil}
		e["IPAddress"] = tc.field
		h.refused("POST", create, body)
	}
	if len(h.reached("POST", "/containers/create")) > 0 {
		t.Fatal("engine saw a create")
	}
}

func TestIPAddressFieldIsStillRefusedWithoutAPin(t *testing.T) {
	h := newHarness(t, scopesJSON)
	body := composeBody(t)
	body["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)["crowsnest-games-net"].(map[string]any)["IPAddress"] = "192.168.0.50"
	h.refused("POST", create, body)
}
