package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gatekeeper/internal/metrics"
)

// CertReloader serves the gateway's TLS certificate through
// tls.Config.GetCertificate and swaps in a new one when asked (SIGHUP)
// or when the certificate/key files change on disk. New handshakes pick
// up the new certificate; connections already established keep the one
// they negotiated, so nothing in flight is dropped. A reload that fails —
// unreadable files, a key that doesn't match the certificate, an expired
// certificate — is logged and the previous certificate stays in use.
//
// Certificate and key material is never logged; only the subject,
// serial number, and expiry are.
type CertReloader struct {
	metrics *metrics.Metrics
	logger  *log.Logger

	mu                  sync.Mutex // serialises loads; guards the fields below
	certFile, keyFile   string
	certStamp, keyStamp fileStamp // as of the last load attempt

	current atomic.Pointer[tls.Certificate]
}

// fileStamp identifies a version of a file well enough to notice it was
// rewritten.
type fileStamp struct {
	modTime time.Time
	size    int64
}

// NewCertReloader loads the initial certificate, failing if it can't be
// used. m may be nil.
func NewCertReloader(certFile, keyFile string, m *metrics.Metrics, logger *log.Logger) (*CertReloader, error) {
	if logger == nil {
		logger = log.Default()
	}
	r := &CertReloader{metrics: m, logger: logger, certFile: certFile, keyFile: keyFile}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current.Load(), nil
}

// Certificate returns the certificate currently being served.
func (r *CertReloader) Certificate() *tls.Certificate {
	return r.current.Load()
}

// Reload re-reads the certificate and key from their files. On failure
// the previous certificate stays in use and the error is returned (and
// logged).
func (r *CertReloader) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reloadLocked()
}

// SetFiles points the reloader at new certificate/key paths and loads
// them. If loading fails, the old paths and certificate are kept.
func (r *CertReloader) SetFiles(certFile, keyFile string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if certFile == r.certFile && keyFile == r.keyFile {
		return r.reloadLocked()
	}
	oldCert, oldKey := r.certFile, r.keyFile
	r.certFile, r.keyFile = certFile, keyFile
	if err := r.reloadLocked(); err != nil {
		r.certFile, r.keyFile = oldCert, oldKey
		r.certStamp, r.keyStamp = stat(oldCert), stat(oldKey)
		return err
	}
	return nil
}

func (r *CertReloader) reloadLocked() error {
	r.certStamp, r.keyStamp = stat(r.certFile), stat(r.keyFile)

	cert, err := loadCertificate(r.certFile, r.keyFile)
	if err != nil {
		r.record(false)
		if r.current.Load() != nil {
			r.logger.Printf("tls: certificate reload failed, keeping the previous certificate: %v", err)
		}
		return err
	}
	r.current.Store(cert)
	r.record(true)
	if r.metrics != nil {
		r.metrics.SetServerCertificateExpiry(cert.Leaf.NotAfter)
	}
	r.logger.Printf("tls: loaded server certificate %s (subject %q, serial %X, expires %s)",
		r.certFile, cert.Leaf.Subject.String(), cert.Leaf.SerialNumber, cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// loadCertificate loads and sanity-checks a certificate/key pair.
// Errors name the files but never include their contents.
func loadCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: loading certificate %s / key %s: %w", certFile, keyFile, err)
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("tls: parsing certificate %s: %w", certFile, err)
		}
		cert.Leaf = leaf
	}
	if now := time.Now(); now.After(cert.Leaf.NotAfter) {
		return nil, fmt.Errorf("tls: certificate %s expired at %s", certFile, cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return &cert, nil
}

// watch reloads the certificate whenever its files change, checking
// every interval until ctx is done. A failed attempt isn't retried until
// the files change again, so a half-written pair (new certificate, old
// key) is retried as soon as the second file lands.
func (r *CertReloader) watch(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reloadIfChanged()
		}
	}
}

func (r *CertReloader) reloadIfChanged() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if stat(r.certFile) == r.certStamp && stat(r.keyFile) == r.keyStamp {
		return
	}
	r.logger.Printf("tls: certificate files changed on disk, reloading")
	_ = r.reloadLocked()
}

func (r *CertReloader) record(success bool) {
	if r.metrics == nil {
		return
	}
	result := "failure"
	if success {
		result = "success"
	}
	r.metrics.TLSCertificateReloads.WithLabelValues(result).Inc()
}

func stat(path string) fileStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{modTime: fi.ModTime(), size: fi.Size()}
}
