// Package clientip works out the address a request really came from. Every
// place that logs or checks a visitor's IP (sign-in log, audit log, MFA and
// app access rules by IP range) goes through From, so there is one rule.
//
// Keston ID runs behind Cloudflare and Azure Container Apps' ingress. The
// ingress only accepts Cloudflare's IPv4 ranges and the environment's own
// subnet, so the TCP peer is always Azure's Envoy (a private or 100.64/10
// address), never the visitor. In mode "cloudflare" the visitor is read
// from CF-Connecting-IP, which Cloudflare always overwrites, and which is
// honoured only when the immediate peer is itself private/ingress or a
// Cloudflare address: a request that reached the app any other way (a
// misconfigured ingress, a local run) falls back to the peer address, so
// the header cannot be spoofed from the open internet.
package clientip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
)

// Mode is how much to trust the proxy in front.
type Mode string

const (
	// None: the address is the TCP peer. Headers are ignored.
	None Mode = "none"
	// Cloudflare: trust CF-Connecting-IP (or X-Forwarded-For) when the
	// request came through the ingress or Cloudflare.
	Cloudflare Mode = "cloudflare"
)

// Parse reads the KESTON_ID_TRUSTED_PROXY value ("" is none).
func Parse(s string) (Mode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return None, true
	case "cloudflare":
		return Cloudflare, true
	}
	return None, false
}

var mode atomic.Value // Mode

// Configure sets the process-wide mode (once, at start).
func Configure(m Mode) { mode.Store(m) }

// From is the client address of r, or "" if it can't be told.
func From(r *http.Request) string {
	m, _ := mode.Load().(Mode)
	return Resolve(m, r)
}

// Resolve is From with an explicit mode.
func Resolve(m Mode, r *http.Request) string {
	peer, ok := peerAddr(r.RemoteAddr)
	if !ok {
		return ""
	}
	if m == Cloudflare && trustedPeer(peer) {
		if ip, ok := parse(r.Header.Get("CF-Connecting-IP")); ok {
			return ip.String()
		}
		// No Cloudflare header: take the right-most public address in
		// X-Forwarded-For. Entries to the left may be written by the
		// visitor; the right-most one outside our own infrastructure was
		// added by something we trust.
		var hops []string
		for _, v := range r.Header.Values("X-Forwarded-For") {
			hops = append(hops, strings.Split(v, ",")...)
		}
		for i := len(hops) - 1; i >= 0; i-- {
			ip, ok := parse(hops[i])
			if !ok {
				return peer.String() // malformed: trust none of it
			}
			if isPublic(ip) && !inCloudflare(ip) {
				return ip.String()
			}
		}
	}
	return peer.String()
}

func peerAddr(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// parse reads one address, rejecting anything that isn't a plain, usable
// IP (ports, names, zones, unspecified or multicast addresses).
func parse(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() {
		return netip.Addr{}, false
	}
	return a, true
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10") // Azure's ingress proxies (100.100.x.x)

// isPrivate: not routable on the public internet.
func isPrivate(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || cgnat.Contains(a)
}

func isPublic(a netip.Addr) bool { return !isPrivate(a) }

// trustedPeer: the connection came from our own ingress, the environment
// network, or Cloudflare itself.
func trustedPeer(a netip.Addr) bool { return isPrivate(a) || inCloudflare(a) }

// Cloudflare's published ranges (https://www.cloudflare.com/ips/); keep in
// step with infra/cloudflare-ips.json plus Cloudflare's IPv6 list.
var cloudflare = mustPrefixes(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func inCloudflare(a netip.Addr) bool {
	for _, p := range cloudflare {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
