package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainRunsKeygenCommand(t *testing.T) {
	previousArgs, previousStdout := os.Args, os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"awg-service", "keygen"}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Args = previousArgs
		os.Stdout = previousStdout
		_ = reader.Close()
		_ = writer.Close()
	})

	main()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var keypair map[string]string
	if err := json.Unmarshal(output, &keypair); err != nil {
		t.Fatalf("keygen output %q is not JSON: %v", output, err)
	}
	if keypair["privateKey"] == "" || keypair["publicKey"] == "" {
		t.Fatalf("keygen output is missing keys: %v", keypair)
	}
}

func TestMainReportsCommandErrorAndRequestsExit(t *testing.T) {
	previousArgs, previousStderr, previousExit := os.Args, os.Stderr, exitProcess
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var exitCode int
	exitProcess = func(code int) { exitCode = code }
	os.Args = []string{"awg-service", "invalid-command"}
	os.Stderr = writer
	t.Cleanup(func() {
		os.Args, os.Stderr, exitProcess = previousArgs, previousStderr, previousExit
		_ = reader.Close()
		_ = writer.Close()
	})

	main()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(string(output), `unknown command "invalid-command"`) {
		t.Fatalf("stderr = %q, want command error", output)
	}
}

func TestRemoveSavedProfileDeletesOnlyValidatedPeerFile(t *testing.T) {
	dataDir := t.TempDir()
	profileDir := filepath.Join(dataDir, "profiles")
	if err := os.Mkdir(profileDir, 0700); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(profileDir, "iphone.conf")
	if err := os.WriteFile(profilePath, []byte("private key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeSavedProfile(dataDir, "iphone"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Fatalf("profile still exists or stat failed unexpectedly: %v", err)
	}

	outsidePath := filepath.Join(dataDir, "outside.conf")
	if err := os.WriteFile(outsidePath, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeSavedProfile(dataDir, "../outside"); err == nil {
		t.Fatal("path traversal peer name was accepted")
	}
	if _, err := os.Stat(outsidePath); err != nil {
		t.Fatalf("invalid peer name removed an unrelated file: %v", err)
	}
}

func TestRemoveSavedProfileIgnoresMissingFile(t *testing.T) {
	if err := removeSavedProfile(t.TempDir(), "missing"); err != nil {
		t.Fatalf("missing profile should be harmless: %v", err)
	}
}

func TestPrivateKeyFromProfileReadsOnlyInterfaceKey(t *testing.T) {
	profile := `[Interface]
PrivateKey = client-private-key
Address = 10.88.0.2/32

[Peer]
PublicKey = server-public-key
`
	key, err := privateKeyFromProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if key != "client-private-key" {
		t.Fatalf("private key = %q, want key from Interface", key)
	}
}

func TestPrivateKeyFromProfileRejectsMissingOrDuplicateKey(t *testing.T) {
	for _, profile := range []string{
		"[Interface]\nAddress = 10.88.0.2/32\n",
		"[Interface]\nPrivateKey = first\nPrivateKey = second\n",
		"[Peer]\nPrivateKey = peer-key\n",
	} {
		if _, err := privateKeyFromProfile(profile); err == nil {
			t.Errorf("invalid profile accepted: %q", profile)
		}
	}
}

func TestWritePrivateProfileAtomicReplacesWithPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.conf")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateProfileAtomic(path, "new private profile\n"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "new private profile\n" {
		t.Fatalf("profile contents = %q, err = %v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("profile mode = %04o, want 0600", info.Mode().Perm())
	}
}
