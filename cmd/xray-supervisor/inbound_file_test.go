package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type inboundTempFileStub struct {
	path     string
	writeErr error
	chmodErr error
	closeErr error
	closed   bool
}

func (f *inboundTempFileStub) Write(data []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(data), nil
}
func (f *inboundTempFileStub) Chmod(os.FileMode) error { return f.chmodErr }
func (f *inboundTempFileStub) Name() string            { return f.path }
func (f *inboundTempFileStub) Close() error {
	f.closed = true
	return f.closeErr
}

func TestOptionalInboundFileSelectsLaterMatchingInbound(t *testing.T) {
	_, configDir := newProcessTestSupervisor(t)
	configPath := writeTestConfig(t, configDir, "candidates/multiple.json", `{"inbounds":[{"tag":"other","protocol":"socks"},{"tag":"vless-reality","protocol":"vless"}]}`)
	path, found, err := optionalInboundFile(configPath, "vless-reality")
	if err != nil || !found {
		t.Fatalf("selected inbound = %q, %v, %v", path, found, err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	content, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(content), "vless-reality") || strings.Contains(string(content), `"other"`) {
		t.Fatalf("selected inbound config = %s, %v", content, err)
	}
	path, found, err = optionalInboundFile(configPath, "missing")
	if err != nil || found || path != "" {
		t.Fatalf("missing inbound = %q, %v, %v", path, found, err)
	}
}

func TestOptionalInboundFileCleansUpTemporaryFilesOnWriteErrors(t *testing.T) {
	_, configDir := newProcessTestSupervisor(t)
	configPath := writeTestConfig(t, configDir, "candidates/one.json", `{"inbounds":[{"tag":"vless-reality"}]}`)
	for _, testcase := range []struct {
		name string
		stub func(string) *inboundTempFileStub
		want string
	}{
		{name: "write", stub: func(path string) *inboundTempFileStub {
			return &inboundTempFileStub{path: path, writeErr: errors.New("disk full")}
		}, want: "disk full"},
		{name: "chmod", stub: func(path string) *inboundTempFileStub {
			return &inboundTempFileStub{path: path, chmodErr: errors.New("chmod failed")}
		}, want: "chmod failed"},
		{name: "close", stub: func(path string) *inboundTempFileStub {
			return &inboundTempFileStub{path: path, closeErr: errors.New("close failed")}
		}, want: "close failed"},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "temp.json")
			if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
				t.Fatal(err)
			}
			stub := testcase.stub(path)
			_, found, err := optionalInboundFileWith(configPath, "vless-reality", func() (inboundTempFile, error) { return stub, nil })
			if err == nil || !strings.Contains(err.Error(), testcase.want) || found {
				t.Fatalf("temporary file failure = found:%v err:%v", found, err)
			}
			if !stub.closed {
				t.Fatal("temporary file was not closed")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temporary file was not removed: %v", err)
			}
		})
	}
	_, _, err := optionalInboundFileWith(configPath, "vless-reality", func() (inboundTempFile, error) {
		return nil, errors.New("temporary file creation failed")
	})
	if err == nil || !strings.Contains(err.Error(), "temporary file creation failed") {
		t.Fatalf("temporary file creation error = %v", err)
	}
}
