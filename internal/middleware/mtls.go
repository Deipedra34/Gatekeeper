package middleware

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"

	"gatekeeper/internal/config"
)

// certIdentifier turns a verified client certificate into an Identity:
// the client id from the configured certificate field, and the tier from
// the configured CN/OU lists.
type certIdentifier struct {
	field    string
	tierByCN map[string]string
	tierByOU map[string]string
}

func newCertIdentifier(cfg config.MTLSConfig) *certIdentifier {
	ci := &certIdentifier{
		field:    cfg.EffectiveIdentityField(),
		tierByCN: map[string]string{},
		tierByOU: map[string]string{},
	}
	for tier, match := range cfg.Tiers {
		for _, cn := range match.CN {
			ci.tierByCN[cn] = tier
		}
		for _, ou := range match.OU {
			ci.tierByOU[ou] = tier
		}
	}
	return ci
}

// verifiedClientCert returns the client's leaf certificate if — and only
// if — crypto/tls verified it against the client CA pool during the
// handshake. A certificate that was merely presented (client_auth
// "request" or "require") is never returned.
func verifiedClientCert(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

// identify builds the Identity for cert. It fails if the configured
// identity field is empty on this certificate.
func (ci *certIdentifier) identify(cert *x509.Certificate) (Identity, error) {
	var client string
	switch ci.field {
	case config.IdentityFieldSANDNS:
		if len(cert.DNSNames) > 0 {
			client = cert.DNSNames[0]
		}
	case config.IdentityFieldSerial:
		client = fmt.Sprintf("%X", cert.SerialNumber)
	default: // config.IdentityFieldCN
		client = cert.Subject.CommonName
	}
	if client == "" {
		return Identity{}, fmt.Errorf("client certificate has no %s", ci.field)
	}
	return Identity{Method: config.AuthModeMTLS, Client: client, Tier: ci.tier(cert)}, nil
}

// tier maps cert to a tier: a CN match first, then the first of its OUs
// that matches; "" (the default tier) otherwise.
func (ci *certIdentifier) tier(cert *x509.Certificate) string {
	if t, ok := ci.tierByCN[cert.Subject.CommonName]; ok {
		return t
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if t, ok := ci.tierByOU[ou]; ok {
			return t
		}
	}
	return ""
}

type clientCertKey struct{}

// ClientCertificateFrom returns the identity of the verified client
// certificate the request's connection presented, if any. It's set for
// every such request, whatever the route's auth mode, so later middleware
// can use it even where it isn't what authenticated the request.
func ClientCertificateFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(clientCertKey{}).(Identity)
	return id, ok
}

func withClientCertificate(r *http.Request, id Identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), clientCertKey{}, id))
}
