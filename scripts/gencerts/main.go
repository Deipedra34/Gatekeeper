// Command gencerts writes a throwaway development PKI for trying out
// Gatekeeper's TLS and mTLS support: a local CA, a server certificate
// for localhost (and the docker-compose service name), and a client
// certificate signed by the same CA. It needs nothing but Go, so it
// works the same on Linux, macOS, and Windows.
//
//	go run ./scripts/gencerts                 # writes ./certs
//	go run ./scripts/gencerts -out certs -client-cn acme-billing -client-ou premium-customers
//
// The files are for local development only and are git-ignored; never
// use them in production or commit them.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gatekeeper/internal/certgen"
)

func main() {
	out := flag.String("out", "certs", "directory to write the certificates and keys to")
	hosts := flag.String("hosts", "localhost,127.0.0.1,::1,gatekeeper", "comma-separated DNS names / IPs the server certificate is valid for")
	clientCN := flag.String("client-cn", "dev-client", "common name of the client certificate")
	clientOU := flag.String("client-ou", "", "optional organizational unit of the client certificate (e.g. for tier mapping)")
	keyMode := flag.String("key-mode", "0600", "file mode for private keys (octal); use 0644 if a container running as another user must read them")
	force := flag.Bool("force", false, "overwrite existing files")
	flag.Parse()

	mode, err := strconv.ParseUint(*keyMode, 8, 32)
	if err != nil {
		fail("invalid -key-mode %q: %v", *keyMode, err)
	}
	if !*force {
		if _, err := os.Stat(*out + "/ca.pem"); err == nil {
			fail("%s/ca.pem already exists; pass -force to overwrite (this creates a NEW CA, invalidating old certificates)", *out)
		}
	}

	var ous []string
	if *clientOU != "" {
		ous = []string{*clientOU}
	}
	pki, err := certgen.WriteDevPKI(*out, certgen.DevPKIOptions{
		ServerNames: splitList(*hosts),
		ClientCN:    *clientCN,
		ClientOU:    ous,
		KeyMode:     os.FileMode(mode),
	})
	if err != nil {
		fail("%v", err)
	}
	// Forward slashes work in YAML and curl on every OS.
	for _, p := range []*string{&pki.CAFile, &pki.ServerFile, &pki.ServerKeyFile, &pki.ClientFile, &pki.ClientKeyFile} {
		*p = filepath.ToSlash(*p)
	}

	fmt.Printf(`Development PKI written to %s/ (git-ignored — do not commit):

  CA          %s
  server      %s  (key: %s)  valid for: %s
  client      %s  (key: %s)  CN=%s%s

Point Gatekeeper at them:

  tls:
    enabled: true
    cert_file: %q
    key_file: %q
    client_auth: require_and_verify      # or verify_if_given / none
    client_ca_file: %q

Then, e.g.:

  curl --cacert %s --cert %s --key %s https://localhost:8443/api/ping
`,
		*out,
		pki.CAFile,
		pki.ServerFile, pki.ServerKeyFile, *hosts,
		pki.ClientFile, pki.ClientKeyFile, *clientCN, ouSuffix(*clientOU),
		pki.ServerFile, pki.ServerKeyFile, pki.CAFile,
		pki.CAFile, pki.ClientFile, pki.ClientKeyFile,
	)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func ouSuffix(ou string) string {
	if ou == "" {
		return ""
	}
	return ", OU=" + ou
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gencerts: "+format+"\n", args...)
	os.Exit(1)
}
