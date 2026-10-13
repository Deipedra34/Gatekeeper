// Package certgen creates throwaway X.509 certificates — a CA plus server
// and client certificates signed by it — for development and tests. Keys
// are ECDSA P-256. Nothing here is meant for production PKI.
package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// KeyPair is a certificate and its private key, in both parsed and PEM
// form.
type KeyPair struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// Options describes a certificate to issue.
type Options struct {
	CommonName         string
	OrganizationalUnit []string
	DNSNames           []string
	IPAddresses        []net.IP

	// Server and Client select the extended key usages.
	Server bool
	Client bool

	// NotBefore defaults to an hour ago; ValidFor defaults to one year.
	NotBefore time.Time
	ValidFor  time.Duration
}

// NewCA creates a self-signed CA certificate.
func NewCA(commonName string) (*KeyPair, error) {
	return create(&x509.Certificate{
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Gatekeeper development"}},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}, Options{ValidFor: 5 * 365 * 24 * time.Hour}, nil)
}

// Issue creates a certificate described by opts, signed by ca.
func (ca *KeyPair) Issue(opts Options) (*KeyPair, error) {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: opts.CommonName, OrganizationalUnit: opts.OrganizationalUnit},
		DNSNames:    opts.DNSNames,
		IPAddresses: opts.IPAddresses,
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	if opts.Server {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if opts.Client {
		tmpl.ExtKeyUsage = append(tmpl.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	return create(tmpl, opts, ca)
}

func create(tmpl *x509.Certificate, opts Options, parent *KeyPair) (*KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial

	tmpl.NotBefore = opts.NotBefore
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	validFor := opts.ValidFor
	if validFor == 0 {
		validFor = 365 * 24 * time.Hour
	}
	tmpl.NotAfter = tmpl.NotBefore.Add(validFor)

	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// WriteFiles writes the certificate (mode 0644) and private key (keyMode)
// to the given paths.
func (kp *KeyPair) WriteFiles(certPath, keyPath string, keyMode os.FileMode) error {
	if err := os.WriteFile(certPath, kp.CertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, kp.KeyPEM, keyMode); err != nil {
		return err
	}
	// WriteFile only applies the mode when it creates the file.
	return os.Chmod(keyPath, keyMode)
}

// DevPKI is a CA with one server and one client certificate, as written
// by WriteDevPKI.
type DevPKI struct {
	CA, Server, Client *KeyPair

	CAFile, CAKeyFile         string
	ServerFile, ServerKeyFile string
	ClientFile, ClientKeyFile string
}

// DevPKIOptions customises WriteDevPKI.
type DevPKIOptions struct {
	// ServerNames are the DNS names and IP addresses the server
	// certificate is valid for. Defaults to localhost, 127.0.0.1, ::1.
	ServerNames []string
	// ClientCN and ClientOU go into the client certificate's subject.
	ClientCN string
	ClientOU []string
	// KeyMode is the file mode for private keys. Defaults to 0600.
	KeyMode os.FileMode
}

// WriteDevPKI creates a CA, a server certificate, and a client
// certificate, and writes them to dir as ca.pem/ca-key.pem,
// server.pem/server-key.pem, and client.pem/client-key.pem.
func WriteDevPKI(dir string, opts DevPKIOptions) (*DevPKI, error) {
	if len(opts.ServerNames) == 0 {
		opts.ServerNames = []string{"localhost", "127.0.0.1", "::1"}
	}
	if opts.ClientCN == "" {
		opts.ClientCN = "dev-client"
	}
	if opts.KeyMode == 0 {
		opts.KeyMode = 0o600
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	ca, err := NewCA("Gatekeeper Dev CA")
	if err != nil {
		return nil, fmt.Errorf("certgen: CA: %w", err)
	}
	var dnsNames []string
	var ips []net.IP
	for _, n := range opts.ServerNames {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dnsNames = append(dnsNames, n)
		}
	}
	server, err := ca.Issue(Options{CommonName: opts.ServerNames[0], DNSNames: dnsNames, IPAddresses: ips, Server: true})
	if err != nil {
		return nil, fmt.Errorf("certgen: server certificate: %w", err)
	}
	client, err := ca.Issue(Options{CommonName: opts.ClientCN, OrganizationalUnit: opts.ClientOU, DNSNames: []string{opts.ClientCN}, Client: true})
	if err != nil {
		return nil, fmt.Errorf("certgen: client certificate: %w", err)
	}

	p := &DevPKI{
		CA: ca, Server: server, Client: client,
		CAFile: filepath.Join(dir, "ca.pem"), CAKeyFile: filepath.Join(dir, "ca-key.pem"),
		ServerFile: filepath.Join(dir, "server.pem"), ServerKeyFile: filepath.Join(dir, "server-key.pem"),
		ClientFile: filepath.Join(dir, "client.pem"), ClientKeyFile: filepath.Join(dir, "client-key.pem"),
	}
	for _, w := range []struct {
		kp        *KeyPair
		cert, key string
	}{
		{ca, p.CAFile, p.CAKeyFile},
		{server, p.ServerFile, p.ServerKeyFile},
		{client, p.ClientFile, p.ClientKeyFile},
	} {
		if err := w.kp.WriteFiles(w.cert, w.key, opts.KeyMode); err != nil {
			return nil, fmt.Errorf("certgen: writing %s: %w", w.cert, err)
		}
	}
	return p, nil
}
