// Package hysteria manages the TLS certificate material used by the Hysteria 2 inbound.
package hysteria

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CertificateInfo exposes non-secret certificate metadata to the Web UI.
type CertificateInfo struct {
	// Subject contains the Subject value for this object.
	Subject string `json:"subject"`
	// Issuer contains the Issuer value for this object.
	Issuer string `json:"issuer"`
	// DNSNames contains the DNSNames value for this object.
	DNSNames []string `json:"dns_names"`
	// IPAddresses contains the IPAddresses value for this object.
	IPAddresses []string `json:"ip_addresses"`
	// NotBefore contains the NotBefore value for this object.
	NotBefore time.Time `json:"not_before"`
	// NotAfter contains the NotAfter value for this object.
	NotAfter time.Time `json:"not_after"`
	// Fingerprint contains the Fingerprint value for this object.
	Fingerprint string `json:"fingerprint"`
}

// Import validates and writes a certificate and matching private key into a
// new immutable version directory under root.
func Import(root string, certPEM, keyPEM []byte, serverName string) (string, CertificateInfo, error) {
	return importWithVerifier(root, certPEM, keyPEM, serverName, verifyTrusted)
}

// importWithVerifier performs the operation represented by its name.
func importWithVerifier(root string, certPEM, keyPEM []byte, serverName string, verify func([]byte, *x509.Certificate, string) error) (string, CertificateInfo, error) {
	return importWithVerifierAndID(root, certPEM, keyPEM, serverName, verify, newID)
}

// importWithVerifierAndID validates and verifies a certificate before storing it under a generated version ID.
func importWithVerifierAndID(root string, certPEM, keyPEM []byte, serverName string, verify func([]byte, *x509.Certificate, string) error, generateID func() (string, error)) (string, CertificateInfo, error) {
	parsed, info, err := validatePair(certPEM, keyPEM, serverName)
	if err != nil {
		return "", CertificateInfo{}, err
	}
	if err := verify(certPEM, parsed, serverName); err != nil {
		return "", CertificateInfo{}, err
	}
	id, err := generateID()
	if err != nil {
		return "", CertificateInfo{}, err
	}
	if err := writeVersion(root, id, certPEM, keyPEM); err != nil {
		return "", CertificateInfo{}, err
	}
	return id, info, nil
}

// GenerateMkcert creates a temporary mkcert CA, writes an IPv4 SAN certificate
// into a versioned directory, and discards the CA private key afterwards.
func GenerateMkcert(ctx context.Context, root, publicIPv4 string) (string, CertificateInfo, error) {
	return generateMkcertWithID(ctx, root, publicIPv4, newID)
}

// generateMkcertWithID creates a mkcert certificate using an injectable version ID generator.
func generateMkcertWithID(ctx context.Context, root, publicIPv4 string, generateID func() (string, error)) (string, CertificateInfo, error) {
	return generateMkcertWithIDAndTempDirs(ctx, root, publicIPv4, generateID, os.MkdirTemp)
}

// generateMkcertWithIDAndTempDirs creates a certificate with injectable version and temporary-directory operations.
func generateMkcertWithIDAndTempDirs(ctx context.Context, root, publicIPv4 string, generateID func() (string, error), mkdirTemp func(string, string) (string, error)) (string, CertificateInfo, error) {
	if strings.TrimSpace(publicIPv4) == "" {
		return "", CertificateInfo{}, errors.New("public IPv4 is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", CertificateInfo{}, err
	}
	staging, err := mkdirTemp(root, ".mkcert-*")
	if err != nil {
		return "", CertificateInfo{}, err
	}
	defer os.RemoveAll(staging)
	caRoot, err := mkdirTemp("", "xray-easy-mkcert-ca-*")
	if err != nil {
		return "", CertificateInfo{}, err
	}
	defer os.RemoveAll(caRoot)
	leafPath := filepath.Join(staging, "leaf.pem")
	keyPath := filepath.Join(staging, "privkey.pem")
	command := exec.CommandContext(ctx, "mkcert", "-cert-file", leafPath, "-key-file", keyPath, publicIPv4)
	command.Env = append(os.Environ(), "CAROOT="+caRoot)
	if output, err := command.CombinedOutput(); err != nil {
		_ = output // mkcert output is not returned; it can include host paths.
		return "", CertificateInfo{}, errors.New("mkcert could not generate the Hysteria 2 certificate")
	}
	leaf, err := os.ReadFile(leafPath)
	if err != nil {
		return "", CertificateInfo{}, err
	}
	ca, err := os.ReadFile(filepath.Join(caRoot, "rootCA.pem"))
	if err != nil {
		return "", CertificateInfo{}, errors.New("mkcert did not produce its temporary CA certificate")
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return "", CertificateInfo{}, err
	}
	cert := append(append([]byte(nil), leaf...), ca...)
	parsed, info, err := validatePair(cert, key, publicIPv4)
	if err != nil {
		return "", CertificateInfo{}, err
	}
	_ = parsed
	id, err := generateID()
	if err != nil {
		return "", CertificateInfo{}, err
	}
	if err := writeVersion(root, id, cert, key); err != nil {
		return "", CertificateInfo{}, err
	}
	return id, info, nil
}

// Inspect reads only public metadata from a versioned certificate directory.
func Inspect(root, id, serverName string, allowLegacyRoot bool) (CertificateInfo, error) {
	dir, err := versionDirectory(root, id, allowLegacyRoot)
	if err != nil {
		return CertificateInfo{}, err
	}
	cert, err := os.ReadFile(filepath.Join(dir, "fullchain.pem"))
	if err != nil {
		return CertificateInfo{}, err
	}
	key, err := os.ReadFile(filepath.Join(dir, "privkey.pem"))
	if err != nil {
		return CertificateInfo{}, err
	}
	_, info, err := validatePair(cert, key, serverName)
	return info, err
}

// versionDirectory performs the operation represented by its name.
func versionDirectory(root, id string, allowLegacyRoot bool) (string, error) {
	if id == "" && allowLegacyRoot {
		return root, nil
	}
	if len(id) != 32 {
		return "", errors.New("invalid Hysteria 2 certificate version")
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", errors.New("invalid Hysteria 2 certificate version")
	}
	return filepath.Join(root, id), nil
}

// validatePair validates the supplied value.
func validatePair(certPEM, keyPEM []byte, serverName string) (*x509.Certificate, CertificateInfo, error) {
	return validatePairWithMarshaller(certPEM, keyPEM, serverName, x509.MarshalPKIXPublicKey)
}

// validatePairWithMarshaller parses a matching certificate and key using the supplied public-key encoder.
func validatePairWithMarshaller(certPEM, keyPEM []byte, serverName string, marshalPublicKey func(any) ([]byte, error)) (*x509.Certificate, CertificateInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, CertificateInfo{}, errors.New("Hysteria 2 certificate must be PEM encoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, CertificateInfo{}, errors.New("Hysteria 2 certificate is invalid")
	}
	if now := time.Now(); now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, CertificateInfo{}, errors.New("Hysteria 2 certificate is not currently valid")
	}
	if serverName != "" {
		if err := cert.VerifyHostname(serverName); err != nil {
			return nil, CertificateInfo{}, fmt.Errorf("Hysteria 2 certificate does not cover the configured server name: %w", err)
		}
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, CertificateInfo{}, errors.New("Hysteria 2 private key must be PEM encoded")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		if parsed, parseErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); parseErr == nil {
			privateKey = parsed
		} else if parsed, parseErr := x509.ParseECPrivateKey(keyBlock.Bytes); parseErr == nil {
			privateKey = parsed
		} else {
			return nil, CertificateInfo{}, errors.New("Hysteria 2 private key is invalid")
		}
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, CertificateInfo{}, errors.New("Hysteria 2 private key type is not supported")
	}
	publicDER, err := marshalPublicKey(signer.Public())
	if err != nil {
		return nil, CertificateInfo{}, errors.New("Hysteria 2 private key is invalid")
	}
	certDER, err := marshalPublicKey(cert.PublicKey)
	if err != nil || !bytes.Equal(publicDER, certDER) {
		return nil, CertificateInfo{}, errors.New("Hysteria 2 certificate and private key do not match")
	}
	return cert, certificateInfo(cert), nil
}

// verifyTrusted performs the operation represented by its name.
func verifyTrusted(chainPEM []byte, cert *x509.Certificate, serverName string) error {
	return verifyTrustedWithSystemPool(chainPEM, cert, serverName, x509.SystemCertPool)
}

// verifyTrustedWithSystemPool verifies a certificate chain against an injectable system root pool.
func verifyTrustedWithSystemPool(chainPEM []byte, cert *x509.Certificate, serverName string, systemPool func() (*x509.CertPool, error)) error {
	roots, err := systemPool()
	if err != nil || roots == nil {
		return errors.New("system certificate roots are unavailable")
	}
	return verifyTrustedWithRoots(chainPEM, cert, serverName, roots)
}

// verifyTrustedWithRoots performs the operation represented by its name.
func verifyTrustedWithRoots(chainPEM []byte, cert *x509.Certificate, serverName string, roots *x509.CertPool) error {
	if roots == nil {
		return errors.New("system certificate roots are unavailable")
	}
	intermediates := x509.NewCertPool()
	remaining := chainPEM
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		candidate, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr == nil && !bytes.Equal(candidate.Raw, cert.Raw) {
			intermediates.AddCert(candidate)
		}
	}
	_, err := cert.Verify(x509.VerifyOptions{
		DNSName: serverName, Roots: roots, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return errors.New("custom Hysteria 2 certificate is not trusted by the system CA store")
	}
	return nil
}

// certificateInfo performs the operation represented by its name.
func certificateInfo(cert *x509.Certificate) CertificateInfo {
	addresses := make([]string, 0, len(cert.IPAddresses))
	for _, address := range cert.IPAddresses {
		addresses = append(addresses, address.String())
	}
	fingerprint := sha256.Sum256(cert.Raw)
	return CertificateInfo{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), DNSNames: append([]string{}, cert.DNSNames...), IPAddresses: addresses, NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(), Fingerprint: strings.ToUpper(hex.EncodeToString(fingerprint[:]))}
}

// writeVersion writes the supplied value.
func writeVersion(root, id string, cert, key []byte) error {
	return writeVersionWith(root, id, cert, key, versionFileOperations{
		mkdirAll:     os.MkdirAll,
		mkdirTemp:    func(root, pattern string) (string, error) { return os.MkdirTemp(root, pattern) },
		removeAll:    os.RemoveAll,
		writePrivate: writePrivate,
		rename:       os.Rename,
	})
}

// versionFileOperations groups filesystem operations used to publish a certificate version atomically.
type versionFileOperations struct {
	mkdirAll     func(string, os.FileMode) error
	mkdirTemp    func(string, string) (string, error)
	removeAll    func(string) error
	writePrivate func(string, []byte, os.FileMode) error
	rename       func(string, string) error
}

// writeVersionWith stages private certificate files and publishes the version directory after success.
func writeVersionWith(root, id string, cert, key []byte, ops versionFileOperations) error {
	if err := ops.mkdirAll(root, 0o700); err != nil {
		return err
	}
	staging, err := ops.mkdirTemp(root, ".certificate-*")
	if err != nil {
		return err
	}
	defer ops.removeAll(staging)
	if err := ops.writePrivate(filepath.Join(staging, "fullchain.pem"), cert, 0o444); err != nil {
		return err
	}
	if err := ops.writePrivate(filepath.Join(staging, "privkey.pem"), key, 0o400); err != nil {
		return err
	}
	if err := ops.rename(staging, filepath.Join(root, id)); err != nil {
		return err
	}
	return nil
}

// writePrivate writes the supplied value.
func writePrivate(path string, data []byte, mode os.FileMode) error {
	return writePrivateWith(path, data, mode,
		func(path string, flags int, mode os.FileMode) (privateCertificateFile, error) {
			return os.OpenFile(path, flags, mode)
		}, io.Copy)
}

// privateCertificateFile is the writer contract for a staged private certificate file.
type privateCertificateFile interface {
	io.Writer
	// Sync flushes certificate data to storage before the file is closed.
	Sync() error
	// Close releases the staged certificate file.
	Close() error
}

// writePrivateWith creates a private file and copies certificate bytes using injectable I/O operations.
func writePrivateWith(path string, data []byte, mode os.FileMode, open func(string, int, os.FileMode) (privateCertificateFile, error), copyData func(io.Writer, io.Reader) (int64, error)) error {
	file, err := open(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := copyData(file, bytes.NewReader(data)); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// newID performs the operation represented by its name.
func newID() (string, error) {
	return newIDFrom(rand.Reader)
}

// newIDFrom performs the operation represented by its name.
func newIDFrom(source io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
