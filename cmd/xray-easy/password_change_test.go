package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"xray-easy/internal/auth"
)

func TestAdministratorPasswordChangeRequiresCurrentPasswordAndRevokesSessions(t *testing.T) {
	app := newTestApp(t, true)
	path := "/api/auth/password"
	if got := requestJSON(t, app, http.MethodGet, path, nil, true).Code; got != http.StatusMethodNotAllowed {
		t.Fatalf("GET password change status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, path, passwordChangeRequest{CurrentPassword: "correct horse battery", NewPassword: "new password for admin"}, false).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated password change status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, path, nil, true).Code; got != http.StatusBadRequest {
		t.Fatalf("malformed password change status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, path, passwordChangeRequest{CurrentPassword: "wrong password", NewPassword: "new password for admin"}, true).Code; got != http.StatusUnauthorized {
		t.Fatalf("wrong current password status = %d", got)
	}
	if got := requestJSON(t, app, http.MethodPost, path, passwordChangeRequest{CurrentPassword: "correct horse battery", NewPassword: "short"}, true).Code; got != http.StatusBadRequest {
		t.Fatalf("short new password status = %d", got)
	}
	response := requestJSON(t, app, http.MethodPost, path, passwordChangeRequest{CurrentPassword: "correct horse battery", NewPassword: "new password for admin"}, true)
	if response.Code != http.StatusNoContent || !strings.Contains(response.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("successful password change = %d %v", response.Code, response.Header())
	}
	if got := requestJSON(t, app, http.MethodGet, "/api/me", nil, true).Code; got != http.StatusUnauthorized {
		t.Fatalf("old session remained valid: %d", got)
	}
	updated, err := app.server.store.FirstAdmin(t.Context())
	if err != nil || !auth.VerifyPassword("new password for admin", updated.PasswordHash) || auth.VerifyPassword("correct horse battery", updated.PasswordHash) {
		t.Fatalf("password was not rotated: %v", err)
	}
}

func TestPasswordResetCLIReadsConfirmationAndInvalidatesSessions(t *testing.T) {
	app := newTestApp(t, true)
	previous := readCLIPassword
	t.Cleanup(func() { readCLIPassword = previous })
	inputs := [][]byte{[]byte("terminal reset password"), []byte("terminal reset password")}
	readCLIPassword = func(int) ([]byte, error) {
		value := inputs[0]
		inputs = inputs[1:]
		return value, nil
	}
	if err := runAdminCLI(context.Background(), app.server.dataDir, []string{"reset-password"}); err != nil {
		t.Fatal(err)
	}
	admin, err := app.server.store.FirstAdmin(t.Context())
	if err != nil || !auth.VerifyPassword("terminal reset password", admin.PasswordHash) {
		t.Fatalf("reset did not update administrator credentials: %v", err)
	}
	if _, err := app.server.store.SessionAdmin(t.Context(), app.token); err == nil {
		t.Fatal("password reset did not invalidate the old session")
	}
}

func TestReadNewPasswordRejectsTerminalErrorsShortAndMismatchedInput(t *testing.T) {
	previous := readCLIPassword
	t.Cleanup(func() { readCLIPassword = previous })
	readCLIPassword = func(int) ([]byte, error) { return nil, errors.New("terminal unavailable") }
	if _, err := readNewPassword(); err == nil || !strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("terminal error = %v", err)
	}
	readCLIPassword = func(int) ([]byte, error) { return []byte("short"), nil }
	if _, err := readNewPassword(); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("short password error = %v", err)
	}
	call := 0
	readCLIPassword = func(int) ([]byte, error) {
		call++
		if call == 1 {
			return []byte("sufficient password"), nil
		}
		return nil, errors.New("confirmation unavailable")
	}
	if _, err := readNewPassword(); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("confirmation read error = %v", err)
	}
	call = 0
	readCLIPassword = func(int) ([]byte, error) {
		call++
		if call == 1 {
			return []byte("sufficient password"), nil
		}
		return []byte("different password"), nil
	}
	if _, err := readNewPassword(); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("password mismatch error = %v", err)
	}
}

func TestTerminalPasswordInputHandlesLineEndAndClosedInput(t *testing.T) {
	previousStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = previousStdin })
	for _, input := range []string{"secret\n", "secret\r"} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.WriteString(input); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		os.Stdin = reader
		got, err := readTerminalLine()
		_ = reader.Close()
		if err != nil || string(got) != "secret" {
			t.Fatalf("terminal input %q = %q, %v", input, got, err)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	os.Stdin = reader
	if _, err := readTerminalLine(); err == nil {
		t.Fatal("closed terminal input was accepted")
	}
	_ = reader.Close()
	if _, err := readPasswordLineNoEcho(-1); err == nil || !strings.Contains(err.Error(), "not a terminal") {
		t.Fatalf("invalid terminal descriptor error = %v", err)
	}
}
