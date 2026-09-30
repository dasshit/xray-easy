package hysteria

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCertificate(t *testing.T, dnsName string, expires time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	template := x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: dnsName},
		NotBefore: now, NotAfter: expires, DNSNames: []string{dnsName},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(dnsName); ip != nil {
		template.DNSNames = nil
		template.IPAddresses = []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return cert, keyPEM
}

func testCertificateSignedByCA(t *testing.T, dnsName string) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: dnsName},
		NotBefore: now, NotAfter: now.Add(time.Hour), DNSNames: []string{dnsName},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return chain, key, ca
}

func TestValidatePairChecksHostnameExpiryAndKeyMatch(t *testing.T) {
	certPEM, keyPEM := testCertificate(t, "vpn.example.com", time.Now().Add(time.Hour))
	_, info, err := validatePair(certPEM, keyPEM, "vpn.example.com")
	if err != nil {
		t.Fatalf("valid cert/key pair rejected: %v", err)
	}
	if info.Subject == "" || info.Fingerprint == "" || info.NotAfter.IsZero() {
		t.Fatalf("certificate metadata is incomplete: %+v", info)
	}
	if _, _, err := validatePair(certPEM, keyPEM, "other.example.com"); err == nil {
		t.Fatal("certificate with mismatched hostname accepted")
	}
	if _, _, err := validatePair(certPEM, keyPEM, ""); err != nil {
		t.Fatalf("certificate without server-name constraint rejected: %v", err)
	}
	_, wrongKey := testCertificate(t, "vpn.example.com", time.Now().Add(time.Hour))
	if _, _, err := validatePair(certPEM, wrongKey, "vpn.example.com"); err == nil {
		t.Fatal("mismatched private key accepted")
	}
	expiredCert, expiredKey := testCertificate(t, "vpn.example.com", time.Now().Add(-time.Hour))
	if _, _, err := validatePair(expiredCert, expiredKey, "vpn.example.com"); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestCertificateVersionIsAtomicAndRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	cert, key := testCertificate(t, "vpn.example.com", time.Now().Add(time.Hour))
	id := "0123456789abcdef0123456789abcdef"
	if err := writeVersion(root, id, cert, key); err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(root, id, "vpn.example.com", false)
	if err != nil || info.Fingerprint == "" {
		t.Fatalf("inspect stored certificate = %+v, %v", info, err)
	}
	for _, file := range []struct {
		name string
		mode os.FileMode
	}{{"fullchain.pem", 0o444}, {"privkey.pem", 0o400}} {
		stat, err := os.Stat(filepath.Join(root, id, file.name))
		if err != nil || stat.Mode().Perm() != file.mode {
			t.Fatalf("%s permissions = %v, %v; want %o", file.name, stat, err, file.mode)
		}
	}
	if _, err := Inspect(root, "../secret", "vpn.example.com", false); err == nil {
		t.Fatal("path traversal certificate ID accepted")
	}
}

func TestCertificateInfoEncodesMissingDNSNamesAsEmptyArray(t *testing.T) {
	info := certificateInfo(&x509.Certificate{Raw: []byte("certificate without DNS SANs")})
	if info.DNSNames == nil {
		t.Fatal("DNS names should be an empty array, not nil")
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal certificate metadata: %v", err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("decode certificate metadata: %v", err)
	}
	if got := string(payload["dns_names"]); got != "[]" {
		t.Fatalf("dns_names = %s, want []", got)
	}
}

func TestValidatePairRejectsMalformedPEMAndPrivateKeys(t *testing.T) {
	validCert, validKey := testCertificate(t, "vpn.example.com", time.Now().Add(time.Hour))
	for name, pair := range map[string]struct{ cert, key []byte }{
		"missing certificate PEM": {[]byte("not pem"), validKey},
		"wrong PEM block":         {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}), validKey},
		"invalid certificate DER": {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}), validKey},
		"missing private key PEM": {validCert, []byte("not pem")},
		"invalid private key DER": {validCert, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")})},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := validatePair(pair.cert, pair.key, "vpn.example.com"); err == nil {
				t.Fatal("invalid certificate/key input was accepted")
			}
		})
	}
}

func TestValidatePairAcceptsPKCS1AndECDSAPrivateKeys(t *testing.T) {
	rsaCert, rsaKey := testCertificate(t, "rsa.example.test", time.Now().Add(time.Hour))
	rsaBlock, _ := pem.Decode(rsaKey)
	parsed, err := x509.ParsePKCS8PrivateKey(rsaBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(parsed.(*rsa.PrivateKey))})
	if _, _, err := validatePair(rsaCert, pkcs1, "rsa.example.test"); err != nil {
		t.Fatalf("valid PKCS#1 private key rejected: %v", err)
	}

	ecdsaCert, ecdsaKey, _ := testCertificateSignedByCA(t, "ecdsa.example.test")
	block, _ := pem.Decode(ecdsaKey)
	ecdsaParsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecdsaParsed.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})
	if _, _, err := validatePair(ecdsaCert, ecdsaPEM, "ecdsa.example.test"); err != nil {
		t.Fatalf("valid SEC1 private key rejected: %v", err)
	}
}

func TestInspectSupportsLegacyRootAndReportsMissingFiles(t *testing.T) {
	root := t.TempDir()
	cert, key := testCertificate(t, "vpn.example.com", time.Now().Add(time.Hour))
	if err := os.WriteFile(filepath.Join(root, "fullchain.pem"), cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "privkey.pem"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(root, "", "vpn.example.com", true)
	if err != nil || info.Fingerprint == "" {
		t.Fatalf("inspect legacy certificate = %+v, %v", info, err)
	}
	if _, err := Inspect(root, "", "vpn.example.com", false); err == nil {
		t.Fatal("empty version ID was accepted when legacy root was disabled")
	}
	if _, err := Inspect(root, "fedcba9876543210fedcba9876543210", "vpn.example.com", false); err == nil {
		t.Fatal("missing version directory was accepted")
	}
	if err := os.Remove(filepath.Join(root, "privkey.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(root, "", "vpn.example.com", true); err == nil {
		t.Fatal("legacy certificate without its key was accepted")
	}
}

func TestImportRejectsUntrustedCertificateWithoutPersistingIt(t *testing.T) {
	root := t.TempDir()
	cert, key := testCertificate(t, "vpn.example.com", time.Now().Add(time.Hour))
	if _, _, err := Import(root, cert, key, "vpn.example.com"); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("Import() error = %v, want untrusted-certificate error", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("untrusted import left files behind: %v, %v", entries, err)
	}
}

func TestImportPersistsValidatedCertificateAndTrustedVerificationUsesChain(t *testing.T) {
	root := t.TempDir()
	chain, key, rootCertificate := testCertificateSignedByCA(t, "vpn.example.test")
	id, info, err := importWithVerifier(root, chain, key, "vpn.example.test", func(chainPEM []byte, certificate *x509.Certificate, serverName string) error {
		pool := x509.NewCertPool()
		pool.AddCert(rootCertificate)
		return verifyTrustedWithRoots(chainPEM, certificate, serverName, pool)
	})
	if err != nil {
		t.Fatalf("import trusted certificate = %q, %+v, %v", id, info, err)
	}
	if len(id) != 32 || info.Subject == "" || info.Fingerprint == "" {
		t.Fatalf("import result = %q, %+v", id, info)
	}
	if _, err := Inspect(root, id, "vpn.example.test", false); err != nil {
		t.Fatalf("inspect imported certificate: %v", err)
	}
	if err := verifyTrustedWithRoots(chain, mustParseCertificate(t, chain), "vpn.example.test", nil); err == nil {
		t.Fatal("nil root pool unexpectedly trusted a certificate")
	}
	decoratedChain := append(append(append([]byte(nil), chain...), pem.EncodeToMemory(&pem.Block{Type: "NOT A CERTIFICATE", Bytes: []byte("ignored")})...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("malformed")})...)
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(rootCertificate)
	if err := verifyTrustedWithRoots(decoratedChain, mustParseCertificate(t, chain), "vpn.example.test", trustedRoots); err != nil {
		t.Fatalf("chain with unrelated/malformed trailing blocks was rejected: %v", err)
	}
	wrongName := "other.example.test"
	if err := verifyTrustedWithRoots(chain, mustParseCertificate(t, chain), wrongName, func() *x509.CertPool {
		pool := x509.NewCertPool()
		pool.AddCert(rootCertificate)
		return pool
	}()); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("wrong server name verification error = %v", err)
	}
}

func TestImportWithVerifierRejectsValidationTrustAndPersistenceFailures(t *testing.T) {
	cert, key := testCertificate(t, "vpn.example.com", time.Now().Add(time.Hour))
	accept := func([]byte, *x509.Certificate, string) error { return nil }
	if _, _, err := importWithVerifier(t.TempDir(), []byte("bad"), key, "vpn.example.com", accept); err == nil {
		t.Fatal("invalid certificate passed import validation")
	}
	if _, _, err := importWithVerifier(t.TempDir(), cert, key, "vpn.example.com", func([]byte, *x509.Certificate, string) error {
		return errors.New("rejected by verifier")
	}); err == nil || err.Error() != "rejected by verifier" {
		t.Fatalf("untrusted import error = %v", err)
	}
	root := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := importWithVerifier(root, cert, key, "vpn.example.com", accept); err == nil {
		t.Fatal("import into an invalid root succeeded")
	}
}

func mustParseCertificate(t *testing.T, chain []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(chain)
	if block == nil {
		t.Fatal("certificate chain has no PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestWriteVersionRejectsInvalidRootAndExistingVersion(t *testing.T) {
	cert, key := testCertificate(t, "vpn.example.com", time.Now().Add(time.Hour))
	fileRoot := filepath.Join(t.TempDir(), "not-directory")
	if err := os.WriteFile(fileRoot, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeVersion(fileRoot, "0123456789abcdef0123456789abcdef", cert, key); err == nil {
		t.Fatal("certificate root file was accepted")
	}

	root := t.TempDir()
	id := "0123456789abcdef0123456789abcdef"
	if err := os.Mkdir(filepath.Join(root, id), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "keep"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeVersion(root, id, cert, key); err == nil {
		t.Fatal("existing immutable certificate version was overwritten")
	}
	if _, err := os.Stat(filepath.Join(root, id, "keep")); err != nil {
		t.Fatalf("existing certificate version was damaged: %v", err)
	}
}

func TestWritePrivateRejectsExistingFilesAndNewIDReadsExactlySixteenBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(path, []byte("replacement"), 0o600); err == nil {
		t.Fatal("writePrivate overwrote an existing file")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "original" {
		t.Fatalf("existing file changed: %q, %v", contents, err)
	}
	id, err := newIDFrom(strings.NewReader("0123456789abcdef"))
	if err != nil || id != "30313233343536373839616263646566" {
		t.Fatalf("newIDFrom() = %q, %v", id, err)
	}
	if _, err := newIDFrom(strings.NewReader("short")); err == nil {
		t.Fatal("newIDFrom accepted a short random source")
	}
}

func TestVersionDirectoryRejectsNonHexVersion(t *testing.T) {
	if _, err := versionDirectory(t.TempDir(), strings.Repeat("z", 32), false); err == nil {
		t.Fatal("non-hex version ID was accepted")
	}
	root := t.TempDir()
	dir, err := versionDirectory(root, "", true)
	if err != nil || dir != root {
		t.Fatalf("legacy root = %q, %v", dir, err)
	}
}

func TestGenerateMkcertValidatesInputsAndGeneratesVersionedCertificate(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	if _, _, err := GenerateMkcert(ctx, root, " "); err == nil {
		t.Fatal("blank public IPv4 address was accepted")
	}
	fileInsteadOfRoot := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(fileInsteadOfRoot, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenerateMkcert(ctx, filepath.Join(fileInsteadOfRoot, "certs"), "203.0.113.7"); err == nil {
		t.Fatal("unwritable certificate root was accepted")
	}

	cert, key := testCertificate(t, "203.0.113.7", time.Now().Add(time.Hour))
	ca, _ := testCertificate(t, "test-ca.example.test", time.Now().Add(time.Hour))
	fixture := t.TempDir()
	for name, contents := range map[string][]byte{"leaf.pem": cert, "key.pem": key, "rootCA.pem": ca} {
		if err := os.WriteFile(filepath.Join(fixture, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binDir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
cert=
key=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -cert-file) cert="$2"; shift 2 ;;
    -key-file) key="$2"; shift 2 ;;
    *) shift ;;
  esac
done
cp %q "$cert"
cp %q "$key"
cp %q "$CAROOT/rootCA.pem"
`, filepath.Join(fixture, "leaf.pem"), filepath.Join(fixture, "key.pem"), filepath.Join(fixture, "rootCA.pem"))
	if err := os.WriteFile(filepath.Join(binDir, "mkcert"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	id, info, err := GenerateMkcert(ctx, root, "203.0.113.7")
	if err != nil {
		t.Fatalf("GenerateMkcert() error = %v", err)
	}
	if len(id) != 32 || len(info.IPAddresses) != 1 || info.IPAddresses[0] != "203.0.113.7" {
		t.Fatalf("generated certificate = id %q, info %+v", id, info)
	}
	if _, err := os.Stat(filepath.Join(root, id, "privkey.pem")); err != nil {
		t.Fatalf("generated private key was not persisted: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != id {
		t.Fatalf("temporary mkcert files were not cleaned up: %v, %v", entries, err)
	}
}

func TestGenerateMkcertHandlesCommandAndOutputFailures(t *testing.T) {
	ctx := t.Context()
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "mkcert"), []byte("#!/bin/sh\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	if _, _, err := GenerateMkcert(ctx, t.TempDir(), "203.0.113.8"); err == nil || !strings.Contains(err.Error(), "could not generate") {
		t.Fatalf("failed mkcert command error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "mkcert"), []byte("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in -cert-file) : > \"$2\"; shift 2 ;; -key-file) : > \"$2\"; shift 2 ;; *) shift ;; esac; done\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenerateMkcert(ctx, t.TempDir(), "203.0.113.8"); err == nil || !strings.Contains(err.Error(), "temporary CA") {
		t.Fatalf("missing generated files error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "mkcert"), []byte("#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do case \"$1\" in -cert-file) echo invalid > \"$2\"; shift 2 ;; -key-file) echo invalid > \"$2\"; shift 2 ;; *) shift ;; esac; done\nmkdir -p \"$CAROOT\"\necho invalid > \"$CAROOT/rootCA.pem\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenerateMkcert(ctx, t.TempDir(), "203.0.113.8"); err == nil || !strings.Contains(err.Error(), "certificate must be PEM") {
		t.Fatalf("invalid generated certificate error = %v", err)
	}
}

func TestGenerateMkcertReportsMissingLeafAndPrivateKey(t *testing.T) {
	ctx := t.Context()
	binDir := t.TempDir()
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for name, script := range map[string]string{
		"leaf": "#!/bin/sh\nexit 0\n",
		"key": `#!/bin/sh
while [ "$#" -gt 0 ]; do case "$1" in -cert-file) echo leaf > "$2"; shift 2 ;; *) shift ;; esac; done
mkdir -p "$CAROOT"
echo ca > "$CAROOT/rootCA.pem"
`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(binDir, "mkcert"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			_, _, err := GenerateMkcert(ctx, t.TempDir(), "203.0.113.9")
			if err == nil {
				t.Fatal("mkcert succeeded without its output files")
			}
			if name == "leaf" && !strings.Contains(err.Error(), "leaf.pem") {
				t.Fatalf("missing leaf error = %v", err)
			}
			if name == "key" && !strings.Contains(err.Error(), "privkey.pem") {
				t.Fatalf("missing key error = %v", err)
			}
		})
	}
}
