package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeyboardNavigationAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		kind  keyKind
	}{
		{"enter", "\n", keyEnter},
		{"return", "\r", keyEnter},
		{"tab", "\t", keyTab},
		{"backspace", "\x7f", keyBackspace},
		{"up", "\x1b[A", keyUp},
		{"down", "\x1b[B", keyDown},
		{"right", "\x1b[C", keyRight},
		{"left", "\x1b[D", keyLeft},
		{"escape", "\x1b", keyEscape},
		{"letter", "x", keyCharacter},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			w := newWizard(strings.NewReader(tc.input), &output)
			defer w.close()
			key, err := w.key(context.Background())
			if err != nil || key.kind != tc.kind {
				t.Fatalf("key = %+v, %v; want %v", key, err, tc.kind)
			}
		})
	}
	var output bytes.Buffer
	w := newWizard(strings.NewReader(""), &output)
	defer w.close()
	if _, err := w.key(context.Background()); err == nil || !strings.Contains(err.Error(), "input ended") {
		t.Fatalf("closed input error = %v", err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := w.key(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
}

func TestPortsCanBeEditedWithArrowsAndBackspace(t *testing.T) {
	var output bytes.Buffer
	input := "\x1b[B9099\x7f0\n"
	w := newWizard(strings.NewReader(input), &output)
	defer w.close()
	w.step(2, "Configuration")
	public, ui, err := w.ports(context.Background(), 443, 8080)
	if err != nil || public != 443 || ui != 9090 {
		t.Fatalf("ports = %d/%d, %v", public, ui, err)
	}
	if !strings.Contains(output.String(), "9090") {
		t.Fatal("edited Web UI port was not rendered")
	}

	output.Reset()
	w = newWizard(strings.NewReader("\t\x1b[A4443\n8080\n"), &output)
	defer w.close()
	w.step(2, "Configuration")
	public, ui, err = w.ports(context.Background(), 443, 8080)
	if err != nil || public != 4443 || ui != 8080 {
		t.Fatalf("arrow navigation ports = %d/%d, %v", public, ui, err)
	}

	output.Reset()
	w = newWizard(strings.NewReader("\x1b"), &output)
	defer w.close()
	w.step(2, "Configuration")
	_, _, err = w.ports(context.Background(), 443, 8080)
	if !errors.Is(err, errCancelled) {
		t.Fatalf("Esc did not cancel port setup: %v", err)
	}
}

func TestReviewActionsAndVisibleFeedback(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  bool
	}{
		{"\x1b[B\n", false},
		{"\x1b[C\n", false},
		{"\x1b", false},
		{"no\n", false},
		{"n\x7fy\n", true},
		{"yes\n", true},
	} {
		var output bytes.Buffer
		w := newWizard(strings.NewReader(tc.input), &output)
		w.review(configuration{project: defaultProject, version: defaultVersion, public: 443, ui: 8080})
		got, err := w.confirm(context.Background())
		w.close()
		if err != nil || got != tc.want {
			t.Fatalf("input %q: choice = %v, %v; want %v", tc.input, got, err, tc.want)
		}
		if !strings.Contains(output.String(), "Review installation") || !strings.Contains(output.String(), "Compose project") {
			t.Fatalf("review details missing from UI for %q", tc.input)
		}
	}
}

func TestDockerOutputIsBoundedAndCannotControlTerminal(t *testing.T) {
	var output bytes.Buffer
	w := newWizard(strings.NewReader(""), &output)
	defer w.close()
	w.step(4, "Building and starting containers")
	for i := range 120 {
		_, _ = w.Write([]byte(fmt.Sprintf("layer %03d\n", i)))
	}
	_, _ = w.Write([]byte("\x1b[31mwarning\rpartial"))
	if len(w.logs) != 100 {
		t.Fatalf("retained %d log lines, want 100", len(w.logs))
	}
	if strings.Contains(w.logTail(3), "layer 000") || !strings.Contains(w.logTail(3), "partial") {
		t.Fatalf("incorrect bounded log tail: %s", w.logTail(3))
	}
	if strings.Contains(w.logTail(3), "\x1b") {
		t.Fatal("Docker escape sequence reached displayed logs")
	}
	_, _ = w.Write([]byte(strings.Repeat("x", maxInstallerLogLine+800) + "read-only file system\n"))
	if !strings.Contains(w.logTail(1), "read-only file system") {
		t.Fatal("long OCI error was truncated before its cause")
	}
	if len(w.logs[len(w.logs)-1]) > maxInstallerLogLine {
		t.Fatal("unbounded OCI error reached the log buffer")
	}
	if !strings.Contains(output.String(), "Docker Compose output") {
		t.Fatal("Docker progress panel was not rendered")
	}
}

func TestInstallerShowsDoctorProgressAfterComposeHealth(t *testing.T) {
	var output bytes.Buffer
	w := newWizard(strings.NewReader(""), &output)
	defer w.close()
	w.step(4, "Verifying the installation")
	if !strings.Contains(output.String(), "Running final doctor checks...") {
		t.Fatal("verification step still shows the Compose health wait status")
	}
	w.step(4, "Doctor checks completed")
	if !strings.Contains(output.String(), "Doctor checks completed.") {
		t.Fatal("completed doctor step was not shown in the installer")
	}
	w.step(4, "Doctor checks failed")
	if !strings.Contains(output.String(), "Doctor found failures; installation is preserved.") || !strings.Contains(output.String(), "Services kept running; see doctor details above.") {
		t.Fatal("failed doctor step did not show that installation state is preserved")
	}
}

func TestTerminalRenderingHandlesSmallScreenAndStyles(t *testing.T) {
	var output bytes.Buffer
	w := newWizard(strings.NewReader(""), &output)
	defer w.close()
	w.mu.Lock()
	w.width, w.height, w.noColor = 50, 18, false
	w.renderLocked()
	w.mu.Unlock()
	if !strings.Contains(output.String(), "Enlarge your terminal") {
		t.Fatal("small terminal guidance missing")
	}
	output.Reset()
	w.mu.Lock()
	w.width, w.height = 120, 32
	w.renderLocked()
	w.mu.Unlock()
	if !strings.Contains(output.String(), "\x1b[1;97;44m") {
		t.Fatal("color header was not rendered")
	}
	if got := clipRunes("abcdef", 3); got != "abc" {
		t.Fatalf("clipped text = %q", got)
	}
	if got := lastRune("aβ"); got != "β" {
		t.Fatalf("last rune = %q", got)
	}
	for _, style := range []string{"accent", "selected", "dim", "border", "notice", "normal"} {
		if w.color(style) == "" {
			t.Fatalf("color for %s missing", style)
		}
	}
	w.noColor = true
	if w.color("selected") != "" {
		t.Fatal("NO_COLOR was not honored")
	}
}

func TestWizardBlocksPortAndConfirmationInputOnSmallTerminal(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		run   func(*wizard) error
	}{
		{"ports", "1\x1b", func(w *wizard) error { _, _, err := w.ports(context.Background(), 443, 8080); return err }},
		{"confirmation", "y\x1b", func(w *wizard) error { _, err := w.confirm(context.Background()); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			w := newWizard(strings.NewReader(test.input), &output)
			defer w.close()
			w.mu.Lock()
			w.width, w.height = 50, 18
			w.mu.Unlock()
			if err := test.run(w); err != nil && !errors.Is(err, errCancelled) {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "Enlarge the terminal") {
				t.Fatal("small terminal did not block input")
			}
		})
	}
}

func TestTerminalSessionRestoresSettingsAndMainRuns(t *testing.T) {
	binDir := t.TempDir()
	sttyLog := filepath.Join(binDir, "stty.log")
	stty := "#!/bin/sh\necho \"$*\" >> \"$FAKE_STTY_LOG\"\ncase \"$1\" in -g) echo original-settings;; size) echo 24 80;; esac\n"
	if err := os.WriteFile(filepath.Join(binDir, "stty"), []byte(stty), 0o700); err != nil {
		t.Fatal(err)
	}
	docker := "#!/bin/sh\nif [ \"$1\" = compose ] && [ \"$2\" = version ]; then echo v2.33.1; exit 0; fi\nif [ \"$1\" = info ]; then echo 28.0.0; exit 0; fi\nif [ \"$1\" = compose ] && [ \"$4\" = up ]; then echo 'Container control-plane Started'; fi\n"
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte(docker), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_STTY_LOG", sttyLog)
	t.Setenv("TERM", "xterm-256color")
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := io.WriteString(writer, "\n\n\n\n\n\n\n\n"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	output, err := os.CreateTemp(t.TempDir(), "terminal-output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	var errorsOut bytes.Buffer
	root := t.TempDir()
	if code := runMain([]string{root}, input, output, &errorsOut); code != 0 {
		t.Fatalf("runMain exit code %d: %s", code, errorsOut.String())
	}
	content := readFile(t, output.Name())
	if !strings.Contains(content, "\x1b[?1049h") || !strings.Contains(content, "\x1b[?1049l") {
		t.Fatal("alternate screen was not entered and restored")
	}
	if !strings.Contains(content, "ssh -N -L 8080:127.0.0.1:8080") {
		t.Fatal("next steps were not printed after restoring terminal")
	}
	if !strings.Contains(content, "Container control-plane Started") {
		t.Fatal("Docker output was not shown inside the installer")
	}
	log := readFile(t, sttyLog)
	if !strings.Contains(log, "-icanon -echo") || !strings.Contains(log, "original-settings") {
		t.Fatalf("terminal settings were not restored: %s", log)
	}
	readPrivateFile(t, filepath.Join(root, ".env"))
}

func TestRunMainRejectsBadArgumentsAndUnavailableTerminal(t *testing.T) {
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	output, err := os.CreateTemp(t.TempDir(), "output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	var errorsOut bytes.Buffer
	if code := runMain(nil, input, output, &errorsOut); code != 2 {
		t.Fatalf("missing argument exit code = %d", code)
	}
	if code := runMain([]string{t.TempDir()}, input, output, &errorsOut); code != 1 {
		t.Fatalf("unavailable terminal exit code = %d", code)
	}
	if !strings.Contains(errorsOut.String(), "Cannot open terminal") {
		t.Fatal("terminal error was not explained")
	}
}

func TestTerminalSizeFallbackAndResize(t *testing.T) {
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	width, height := terminalSize(input)
	if width != 100 || height != 30 {
		t.Fatalf("fallback size = %dx%d", width, height)
	}
	var output bytes.Buffer
	w := newWizard(input, &output)
	defer w.close()
	w.resize <- os.Interrupt
	deadline := time.After(time.Second)
	for {
		w.mu.Lock()
		got := output.Len()
		w.mu.Unlock()
		if got > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("resize did not redraw")
		case <-time.After(time.Millisecond):
		}
	}
}
