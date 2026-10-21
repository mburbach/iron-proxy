package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Exercise the verifier used by upstream TLS even when an operator explicitly
// trusts the issuing CA. Root-store removal alone cannot protect this case.
func TestRejectCompromisedEMudhraChains(t *testing.T) {
	cases, err := filepath.Glob("testdata/emudhra/*.pem")
	require.NoError(t, err)
	require.Len(t, cases, 12)
	for _, path := range cases {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var certs []*x509.Certificate
			for len(data) > 0 {
				block, rest := pem.Decode(data)
				require.NotNil(t, block)
				cert, err := x509.ParseCertificate(block.Bytes)
				require.NoError(t, err)
				certs = append(certs, cert)
				data = []byte(strings.TrimSpace(string(rest)))
			}
			require.GreaterOrEqual(t, len(certs), 2)
			roots := x509.NewCertPool()
			roots.AddCert(certs[len(certs)-1])
			intermediates := x509.NewCertPool()
			for i := 0; i < len(certs)-1; i++ {
				require.NoError(t, certs[i].CheckSignatureFrom(certs[i+1]))
				if i > 0 {
					intermediates.AddCert(certs[i])
				}
			}
			_, err = certs[0].Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: intermediates,
				DNSName:     strings.TrimSuffix(filepath.Base(path), ".pem"),
				CurrentTime: certs[0].NotBefore.Add(time.Minute),
			})
			var invalid x509.CertificateInvalidError
			require.ErrorAs(t, err, &invalid)
			require.Equal(t, x509.NoValidChains, invalid.Reason)
		})
	}
}

func TestUpstreamVerifierAcceptsUnaffectedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	cert := srv.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	_, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: cert.NotBefore.Add(time.Minute)})
	require.NoError(t, err)
}
