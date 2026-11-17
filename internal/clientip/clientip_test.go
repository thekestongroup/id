package clientip

import (
	"net/http"
	"testing"
)

func req(remote string, h map[string]string, xff ...string) *http.Request {
	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = remote
	for k, v := range h {
		r.Header.Set(k, v)
	}
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestResolve(t *testing.T) {
	cf := func(v string) map[string]string { return map[string]string{"CF-Connecting-IP": v} }
	tests := []struct {
		name string
		mode Mode
		r    *http.Request
		want string
	}{
		{"none ignores spoofed CF header", None, req("203.0.113.5:1234", cf("1.2.3.4")), "203.0.113.5"},
		{"none ignores spoofed XFF", None, req("10.40.0.4:1", nil, "1.2.3.4"), "10.40.0.4"},
		{"cf header via ingress", Cloudflare, req("100.100.0.7:443", cf("198.51.100.9")), "198.51.100.9"},
		{"cf header via cloudflare peer", Cloudflare, req("172.64.1.1:443", cf("198.51.100.9")), "198.51.100.9"},
		{"cf header via environment subnet", Cloudflare, req("10.40.0.5:1", cf("198.51.100.9")), "198.51.100.9"},
		{"cf header from untrusted peer is spoof", Cloudflare, req("203.0.113.5:1", cf("1.2.3.4")), "203.0.113.5"},
		{"cf header IPv6", Cloudflare, req("100.100.0.7:1", cf("2001:db8::1")), "2001:db8::1"},
		{"cf header IPv4-mapped", Cloudflare, req("100.100.0.7:1", cf("::ffff:198.51.100.9")), "198.51.100.9"},
		{"IPv6 peer", None, req("[2001:db8::2]:80", nil), "2001:db8::2"},
		{"garbage cf header falls back to XFF", Cloudflare, req("100.100.0.7:1", cf("not-an-ip"), "198.51.100.9"), "198.51.100.9"},
		{"garbage everywhere falls back to peer", Cloudflare, req("100.100.0.7:1", cf("zzz"), "also bad"), "100.100.0.7"},
		{"cf header with port rejected", Cloudflare, req("100.100.0.7:1", cf("198.51.100.9:80")), "100.100.0.7"},
		{"unspecified cf header rejected", Cloudflare, req("100.100.0.7:1", cf("0.0.0.0")), "100.100.0.7"},
		{"missing header uses XFF", Cloudflare, req("100.100.0.7:1", nil, "198.51.100.9, 172.64.1.1"), "198.51.100.9"},
		{"XFF skips private and cloudflare hops", Cloudflare, req("100.100.0.7:1", nil, "198.51.100.9, 10.1.1.1, 104.16.0.1"), "198.51.100.9"},
		{"XFF right-most wins over visitor-written left", Cloudflare, req("100.100.0.7:1", nil, "6.6.6.6, 198.51.100.9"), "198.51.100.9"},
		{"XFF from untrusted peer ignored", Cloudflare, req("203.0.113.5:1", nil, "6.6.6.6"), "203.0.113.5"},
		{"XFF only private falls back to peer", Cloudflare, req("100.100.0.7:1", nil, "10.1.1.1"), "100.100.0.7"},
		{"no headers", Cloudflare, req("100.100.0.7:1", nil), "100.100.0.7"},
		{"bad remote addr", Cloudflare, req("garbage", cf("198.51.100.9")), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Resolve(tc.mode, tc.r); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]bool{"": true, "none": true, "Cloudflare": true, "nginx": false} {
		if _, ok := Parse(in); ok != want {
			t.Errorf("Parse(%q) ok=%v", in, ok)
		}
	}
}
