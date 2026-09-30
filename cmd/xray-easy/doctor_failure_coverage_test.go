package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-easy/internal/supervisor"
)

type rejectingDoctorWriter struct{}

func (rejectingDoctorWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func bundleEntry(t *testing.T, output, name string) string {
	t.Helper()
	parts := strings.Split(output, "Bundle saved: ")
	if len(parts) != 2 {
		t.Fatalf("doctor did not report bundle path: %s", output)
	}
	path := strings.SplitN(parts[1], "\n", 2)[0]
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zipper, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer zipper.Close()
	archive := tar.NewReader(zipper)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(archive)
		if err != nil {
			t.Fatal(err)
		}
		if header.Name == name {
			return string(content)
		}
	}
}

func bundleNotes(t *testing.T, output string) string {
	t.Helper()
	return bundleEntry(t, output, "bundle-notes.txt")
}

func TestDoctorBundleRecordsUnavailableSupervisorAndInvalidConfig(t *testing.T) {
	for _, testcase := range []struct {
		name       string
		content    []byte
		statusErr  error
		logsErr    error
		wantNotice string
	}{
		{"supervisor unavailable", []byte(`{"inbounds":[]}`), errors.New("token=hidden-status"), errors.New("logs unavailable"), "supervisor status could not be collected"},
		{"invalid active config", []byte(`{"inbounds":`), nil, nil, "not valid JSON"},
		{"oversized active config", bytes.Repeat([]byte(" "), (2<<20)+1), nil, nil, "exceeds 2 MiB"},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			dataDir, configDir, key := prepareDoctorState(t, true)
			t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
			t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", writeDoctorToken(t, 0o400))
			if err := os.WriteFile(filepath.Join(configDir, "active.json"), testcase.content, 0o600); err != nil {
				t.Fatal(err)
			}
			sup := &doctorSupervisorStub{status: supervisor.Status{State: "running", XrayVersion: "Xray 26.7.28"}, statusErr: testcase.statusErr, logsErr: testcase.logsErr}
			var output bytes.Buffer
			_ = runDoctorBundle(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{})
			if strings.Contains(output.String(), "hidden-status") {
				t.Fatalf("supervisor secret leaked in report: %s", output.String())
			}
			if notes := bundleNotes(t, output.String()); !strings.Contains(notes, testcase.wantNotice) {
				t.Fatalf("bundle notes = %q, want %q", notes, testcase.wantNotice)
			}
		})
	}
}

func TestDoctorBundleReportsOutputAndFilesystemFailures(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", writeDoctorToken(t, 0o400))
	sup := &doctorSupervisorStub{status: supervisor.Status{State: "running"}}
	if err := runDoctorBundle(context.Background(), dataDir, configDir, rejectingDoctorWriter{}, sup, &doctorHandlerStub{}, &doctorStatsStub{}); err == nil || !strings.Contains(err.Error(), "write doctor report") {
		t.Fatalf("output failure = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "diagnostics"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runDoctorBundle(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{}); err == nil || !strings.Contains(err.Error(), "create doctor bundle") {
		t.Fatalf("bundle filesystem failure = %v", err)
	}
}

func TestDoctorCLIDispatchesChecksAndRequestedBundle(t *testing.T) {
	dataDir := t.TempDir()
	configDir := t.TempDir()
	t.Setenv("XRAY_SUPERVISOR_ADDR", "127.0.0.1:1")
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", filepath.Join(t.TempDir(), "missing-token"))
	t.Setenv("XRAY_EASY_MASTER_KEY", "")
	for _, args := range [][]string{nil, {"bundle"}} {
		var output bytes.Buffer
		err := runDoctorCLI(context.Background(), args, dataDir, configDir, &output)
		if err == nil || !strings.Contains(output.String(), "Checks (no persistent changes)") {
			t.Fatalf("doctor %v = %v, output=%s", args, err, output.String())
		}
		if len(args) == 1 && !strings.Contains(output.String(), "Bundle saved:") {
			t.Fatalf("requested bundle was not saved: %s", output.String())
		}
	}
}

func TestDoctorBundleKeepsOnlyRecentBoundedLogs(t *testing.T) {
	dataDir, configDir, key := prepareDoctorState(t, true)
	t.Setenv("XRAY_EASY_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	t.Setenv("XRAY_SUPERVISOR_TOKEN_FILE", writeDoctorToken(t, 0o400))
	logs := make([]string, 101)
	logs[0] = "oldest entry must be removed"
	for i := 1; i < len(logs); i++ {
		logs[i] = "recent entry"
	}
	logs[len(logs)-1] = strings.Repeat("X", 4200)
	sup := &doctorSupervisorStub{status: supervisor.Status{State: "running"}, logs: logs}
	var output bytes.Buffer
	if err := runDoctorBundle(context.Background(), dataDir, configDir, &output, sup, &doctorHandlerStub{}, &doctorStatsStub{}); err != nil {
		t.Fatal(err)
	}
	bounded := bundleEntry(t, output.String(), "xray-errors.log")
	if strings.Contains(bounded, "oldest entry") || strings.Count(bounded, "\n") != 100 || !strings.Contains(bounded, "[truncated]") {
		t.Fatalf("bundle did not bound logs: lines=%d, size=%d", strings.Count(bounded, "\n"), len(bounded))
	}
}
