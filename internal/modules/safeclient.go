package modules

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// PublicClient is an HTTP client for fetching a module the dashboard user named. Unlike the command line, where the
// operator typed the URL on their own machine, the panel runs next to the Docker guard and the rest of the home
// network, so a URL pointing at 10.0.0.1, 127.0.0.1 or a cloud metadata address must not be fetched from here
// (server-side request forgery). The check runs on the address actually dialled, after DNS, so a name that
// resolves to a private address, or a redirect to one, is refused too.
func PublicClient() *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: refusePrivate}
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext:         d.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			Proxy:               nil, // a proxy would do the dialling for us and sidestep the check
			DisableKeepAlives:   true,
		},
	}
}

func refusePrivate(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("not an IP address: %q", host)
	}
	if !isPublic(ip) {
		return errors.New("refusing to fetch from a private, loopback or link-local address")
	}
	return nil
}

func isPublic(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	// Carrier-grade NAT (100.64.0.0/10, Tailscale lives here) and the benchmarking range are not public either.
	for _, p := range []string{"100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "fc00::/7"} {
		if netip.MustParsePrefix(p).Contains(ip) {
			return false
		}
	}
	return true
}
