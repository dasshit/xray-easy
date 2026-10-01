package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"xray-easy/internal/domain"
)

func TestVMessCreationUsesFallbackAndRollsBackFailedLiveAddition(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, true)
	first := createRuntimeVMessClient(t, app, "first")
	if first.UUID == "" || len(app.sup.applyCalls) != 1 {
		t.Fatalf("first VMess profile did not initialize its inbound: %+v applies=%v", first, app.sup.applyCalls)
	}

	// A handler without the optional VMess API must use a full validated apply.
	second := createRuntimeVMessClient(t, app, "second")
	if second.UUID == "" || len(app.sup.applyCalls) != 2 {
		t.Fatalf("missing VMess HandlerService did not use full apply: %+v applies=%v", second, app.sup.applyCalls)
	}

	handler := &recordingVMessHandler{fakeXrayHandler: app.handler}
	app.server.handler = handler
	third := createRuntimeVMessClient(t, app, "third")
	if len(handler.added) != 1 || handler.added[0] != third.Email {
		t.Fatalf("VMess profile did not use live AddUser: %+v", handler.added)
	}

	handler.addErr = errors.New("VMess AddUser rejected")
	failed := requestJSON(t, app, http.MethodPost, "/api/clients", clientRequest{Protocol: string(domain.ProtocolVMess), Name: "failed"}, true)
	if failed.Code != http.StatusBadGateway || !strings.Contains(failed.Body.String(), "VMess AddUser rejected") {
		t.Fatalf("failed VMess live addition = %d %s", failed.Code, failed.Body.String())
	}
	clients, err := app.server.store.ListClients(t.Context())
	if err != nil || len(clients) != 3 {
		t.Fatalf("failed VMess profile was not rolled back: clients=%d err=%v", len(clients), err)
	}
	if len(handler.added) != 2 || handler.added[1] == third.Email {
		t.Fatalf("VMess runtime was changed by rejected addition: %+v", handler.added)
	}
}
