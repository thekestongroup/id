package samlidp

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// ParseSPMetadata reads an app's (service provider's) metadata, returning
// it and where responses go: its default HTTP-POST assertion consumer
// service.
func ParseSPMetadata(data []byte) (*saml.EntityDescriptor, string, error) {
	ed, err := samlsp.ParseMetadata(data)
	if err != nil {
		return nil, "", errors.New("That isn't SAML metadata.")
	}
	if ed.EntityID == "" {
		return nil, "", errors.New("The metadata has no entity ID.")
	}
	var acs string
	for _, sp := range ed.SPSSODescriptors {
		for _, ep := range sp.AssertionConsumerServices {
			if ep.Binding != saml.HTTPPostBinding {
				continue
			}
			if acs == "" || (ep.IsDefault != nil && *ep.IsDefault) {
				acs = ep.Location
			}
		}
	}
	if acs == "" {
		return nil, "", errors.New("The metadata has no HTTP-POST assertion consumer service (ACS) URL.")
	}
	return ed, acs, nil
}

// MakeSPMetadata: metadata for an app set up by hand, from its entity ID
// and ACS URL.
func MakeSPMetadata(entityID, acsURL string) (string, error) {
	ed := saml.EntityDescriptor{
		EntityID: entityID,
		SPSSODescriptors: []saml.SPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
				},
			},
			AssertionConsumerServices: []saml.IndexedEndpoint{{
				Binding:  saml.HTTPPostBinding,
				Location: acsURL,
				Index:    1,
			}},
		}},
	}
	out, err := xml.MarshalIndent(ed, "", "  ")
	return string(out), err
}

// FetchSPMetadata downloads an app's metadata from its metadata URL: https
// only, public addresses only (never Keston's own network), small, quick.
func FetchSPMetadata(ctx context.Context, raw string) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("Enter an https:// metadata URL.")
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil,
			DialContext: (&net.Dialer{Timeout: 5 * time.Second, Control: publicOnly}).DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("Couldn't download the metadata from that URL.")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Couldn't download the metadata from that URL (HTTP %d).", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, errors.New("Couldn't download the metadata from that URL.")
	}
	return data, nil
}

// AllowPrivateMetadata lets FetchSPMetadata reach loopback and private
// addresses (tests only).
var AllowPrivateMetadata = false

func publicOnly(_, address string, _ syscall.RawConn) error {
	if AllowPrivateMetadata {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return errors.New("address not allowed")
	}
	return nil
}
