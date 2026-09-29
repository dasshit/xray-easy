package hysteria

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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
