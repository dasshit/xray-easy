package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"xray-easy/internal/backup"
	"xray-easy/internal/domain"
	"xray-easy/internal/hysteria"
	"xray-easy/internal/maintenance"
	"xray-easy/internal/secret"
	"xray-easy/internal/xray"
)

const hysteriaCertificateMaxBytes = 2 << 20

func (s *server) hysteriaSettingsRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	if _, err := s.authenticated(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	release, err := s.lockHysteriaStorage(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Hysteria 2 storage is busy"})
		return
	}
	defer release()
	status, err := s.hysteriaSettingsStatus(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read Hysteria 2 settings"})
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *server) hysteriaCertificateUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	release, err := s.lockHysteriaStorage(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Hysteria 2 storage is busy"})
		return
	}
	defer release()
	r.Body = http.MaxBytesReader(w, r.Body, hysteriaCertificateMaxBytes)
	if err := r.ParseMultipartForm(256 << 10); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "certificate upload is invalid or exceeds the 2 MiB limit"})
		return
	}
	certPEM, err := readMultipartFile(r.MultipartForm, "fullchain")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "fullchain.pem is required and must be no larger than 2 MiB"})
		return
	}
	keyPEM, err := readMultipartFile(r.MultipartForm, "private_key")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "privkey.pem is required and must be no larger than 2 MiB"})
		return
	}
	serverName := strings.TrimSpace(r.FormValue("server_name"))
	if serverName == "" {
		settings, readErr := s.store.GetSettings(r.Context())
		if readErr != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "complete initial Xray setup first"})
			return
		}
		serverName = settings.PublicHost
	}
	id, certificate, err := hysteria.Import(s.hysteriaTLSDir(), certPEM, keyPEM, serverName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.AddAudit(r.Context(), admin.ID, "hysteria.certificate.import", "hysteria_certificate", id, "imported trusted TLS certificate; fingerprint="+certificate.Fingerprint)
	writeJSON(w, http.StatusCreated, map[string]any{"certificate_id": id, "certificate": certificate})
}

func readMultipartFile(form *multipart.Form, field string) ([]byte, error) {
	files := form.File[field]
	if len(files) != 1 || files[0].Size > hysteriaCertificateMaxBytes {
		return nil, errors.New("invalid file count or size")
	}
	file, err := files[0].Open()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, hysteriaCertificateMaxBytes+1))
	if err != nil || len(data) > hysteriaCertificateMaxBytes {
		return nil, errors.New("file too large")
	}
	return data, nil
}

func (s *server) hysteriaCertificateGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	release, err := s.lockHysteriaStorage(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "Hysteria 2 storage is busy"})
		return
	}
	defer release()
	var request struct {
		IPv4 string `json:"ipv4"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(request.IPv4))
	if err != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "mkcert requires a public IPv4 address"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	id, certificate, err := hysteria.GenerateMkcert(ctx, s.hysteriaTLSDir(), ip.String())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	_ = s.store.AddAudit(r.Context(), admin.ID, "hysteria.certificate.generate", "hysteria_certificate", id, "generated temporary-CA certificate for IPv4; fingerprint="+certificate.Fingerprint)
	writeJSON(w, http.StatusCreated, map[string]any{"certificate_id": id, "certificate": certificate})
}

func (s *server) hysteriaSettingsStatus(ctx context.Context) (hysteriaSettingsResponse, error) {
	settings, err := loadHysteriaSettings(ctx, s.store)
	if err != nil {
		return hysteriaSettingsResponse{}, err
	}
	serverSettings, err := s.store.GetSettings(ctx)
	if err != nil {
		return hysteriaSettingsResponse{}, err
	}
	host := settings.Host
	if host == "" {
		host = serverSettings.PublicHost
	}
	response := hysteriaSettingsResponse{
		Enabled: settings.Enabled, State: "off", Host: host, UDPPort: s.publicPort,
		TLSMode: settings.TLSMode, TLSServerName: settings.EffectiveTLSServerName(serverSettings.PublicHost),
		TLSCertIP: settings.TLSCertIP, CertificateID: settings.CertificateID,
		UDPIdleTimeout: settings.UDPIdleTimeout, MasqueradeType: settings.MasqueradeType,
		MasqueradeString: settings.MasqueradeString,
		InsecureURI:      settings.TLSMode == domain.HysteriaTLSSelfSigned || settings.TLSMode == domain.HysteriaTLSLegacy,
	}
	certificate, certErr := hysteria.Inspect(s.hysteriaTLSDir(), settings.CertificateID, response.TLSServerName, settings.CertificateID == "")
	if certErr == nil {
		response.Certificate = &certificate
	} else {
		response.CertificateError = certErr.Error()
	}
	inboundPresent := hasInboundTag(filepath.Join(s.configDir, "active.json"), xray.HysteriaInboundTag)
	if settings.Enabled {
		switch {
		case certErr != nil:
			response.State = "error"
		case !inboundPresent:
			response.State = "error"
			response.RuntimeError = "Hysteria 2 is enabled in settings but its inbound is absent from the active Xray configuration"
		default:
			response.State = "on"
		}
	} else if certErr != nil {
		response.State = "needs_certificate"
	} else if inboundPresent {
		response.State = "error"
		response.RuntimeError = "Hysteria 2 inbound is present in the active Xray configuration while the transport is disabled"
	} else {
		response.State = "ready"
	}
	return response, nil
}

func (s *server) hysteriaSettingsPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	var request hysteriaSettingsRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	base, err := loadHysteriaSettings(r.Context(), s.store)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read Hysteria 2 settings"})
		return
	}
	node, err := s.store.GetSettings(r.Context())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "settings_incomplete", "error": "complete initial Xray setup first"})
		return
	}
	candidate := domain.HysteriaSettings{
		Enabled: request.Enabled, Host: strings.TrimSpace(request.Host), TLSMode: strings.TrimSpace(request.TLSMode),
		TLSCertIP: strings.TrimSpace(request.TLSCertIP), TLSServerName: strings.TrimSpace(request.TLSServerName),
		CertificateID: strings.TrimSpace(request.CertificateID), UDPIdleTimeout: request.UDPIdleTimeout,
		MasqueradeType: strings.TrimSpace(request.MasqueradeType), MasqueradeString: request.MasqueradeString,
	}
	if err := candidate.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	if candidate.Host != "" {
		host, err := domain.NormalizePublicHost(candidate.Host)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "Hysteria 2 host must be a DNS name or public IP"})
			return
		}
		candidate.Host = host
	}
	serverName := candidate.EffectiveTLSServerName(node.PublicHost)
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list profiles"})
		return
	}
	vmessExpected := vmessInboundExpected(clients)
	if candidate.Enabled || vmessExpected {
		if _, err := hysteria.Inspect(s.hysteriaTLSDir(), candidate.CertificateID, serverName, candidate.CertificateID == ""); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"code": "certificate_not_ready", "error": "a matching, valid TLS certificate is required by the enabled transports", "detail": err.Error()})
			return
		}
	}
	diff := hysteriaSettingsDiff(base, candidate, node)
	if len(diff) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"changed": false, "settings": s.hysteriaPublicSettings(candidate, node, nil)})
		return
	}
	changeID, err := randomID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not create Hysteria 2 change"})
		return
	}
	activePath := filepath.Join(s.configDir, "active.json")
	activeHysteria := hasInboundTag(activePath, xray.HysteriaInboundTag)
	activeVMess := hasInboundTag(activePath, xray.VMessInboundTag)
	changeVMessTLS := (vmessExpected || activeVMess) && (vmessCertificateChanged(base, candidate) || (!activeVMess && vmessExpected))
	changeHysteria := activeHysteria || candidate.Enabled
	consequences := make([]string, 0, 4)
	if changeHysteria {
		if changeVMessTLS {
			consequences = append(consequences, "Hysteria 2 and VMess inbounds will be changed; the VLESS inbound remains active", "active Hysteria 2 and VMess connections may briefly reconnect")
		} else {
			consequences = append(consequences, "only the Hysteria 2 inbound will be changed; the VLESS inbound remains active", "active Hysteria 2 connections may briefly reconnect")
		}
	} else {
		consequences = append(consequences, "Hysteria 2 remains disabled")
	}
	if changeVMessTLS {
		consequences = append(consequences, "the VMess TLS certificate or server name will be updated; active VMess connections may briefly reconnect")
	}
	if candidate.Host != base.Host || candidate.TLSServerName != base.TLSServerName || candidate.TLSMode != base.TLSMode || candidate.CertificateID != base.CertificateID {
		consequences = append(consequences, "existing Hysteria 2 or VMess profiles may need to be imported again")
	}
	pending := pendingHysteriaChange{ID: changeID, AdminID: admin.ID, Base: base, Candidate: candidate, ExpectedConfirmation: "APPLY", Diff: diff, Consequences: consequences, ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	s.hysteriaMu.Lock()
	if s.pendingHysteria == nil {
		s.pendingHysteria = make(map[string]pendingHysteriaChange)
	}
	for id, change := range s.pendingHysteria {
		if change.AdminID == admin.ID {
			delete(s.pendingHysteria, id)
		}
	}
	s.pendingHysteria[changeID] = pending
	s.hysteriaMu.Unlock()
	response := map[string]any{
		"changed": true, "change_id": changeID, "expires_in": 600,
		"expected_confirmation": pending.ExpectedConfirmation, "requires_confirmation": true,
		"diff": diff, "consequences": consequences,
		"settings": s.hysteriaPublicSettings(candidate, node, nil),
	}
	writeJSON(w, http.StatusOK, response)
}

func vmessCertificateChanged(base, candidate domain.HysteriaSettings) bool {
	return base.CertificateID != candidate.CertificateID
}

func hysteriaSettingsDiff(base, candidate domain.HysteriaSettings, node domain.Settings) []settingsDiff {
	values := []settingsDiff{}
	add := func(field, from, to string) {
		if from != to {
			values = append(values, settingsDiff{Field: field, From: from, To: to})
		}
	}
	add("enabled", fmt.Sprint(base.Enabled), fmt.Sprint(candidate.Enabled))
	baseHost, candidateHost := base.Host, candidate.Host
	if baseHost == "" {
		baseHost = node.PublicHost
	}
	if candidateHost == "" {
		candidateHost = node.PublicHost
	}
	add("host", baseHost, candidateHost)
	add("tls_mode", base.TLSMode, candidate.TLSMode)
	add("tls_server_name", base.EffectiveTLSServerName(node.PublicHost), candidate.EffectiveTLSServerName(node.PublicHost))
	add("certificate", base.CertificateID, candidate.CertificateID)
	add("udp_idle_timeout", fmt.Sprint(base.UDPIdleTimeout), fmt.Sprint(candidate.UDPIdleTimeout))
	add("masquerade_type", base.MasqueradeType, candidate.MasqueradeType)
	add("masquerade_string", base.MasqueradeString, candidate.MasqueradeString)
	return values
}

func (s *server) hysteriaSettingsApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	var request hysteriaApplyRequest
	if err := decodeJSON(r, &request); err != nil || strings.TrimSpace(request.ChangeID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "change_id is required"})
		return
	}
	s.hysteriaMu.Lock()
	pending, ok := s.pendingHysteria[request.ChangeID]
	if !ok || pending.AdminID != admin.ID || time.Now().UTC().After(pending.ExpiresAt) || pending.Applying {
		s.hysteriaMu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]any{"code": "confirmation_expired", "error": "Hysteria 2 change is expired or already applying"})
		return
	}
	if strings.TrimSpace(request.Confirmation) != pending.ExpectedConfirmation {
		s.hysteriaMu.Unlock()
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "confirmation_required", "error": "type APPLY to confirm the Hysteria 2 change"})
		return
	}
	pending.Applying = true
	s.pendingHysteria[request.ChangeID] = pending
	s.hysteriaMu.Unlock()

	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	maintenanceLock, err := maintenance.Acquire(r.Context(), s.maintenancePath)
	if err != nil {
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "apply_pending", "error": "maintenance lock is unavailable"})
		return
	}
	defer maintenanceLock.Close()
	current, err := s.store.GetHysteriaSettings(r.Context())
	if err != nil || current != pending.Base {
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusConflict, map[string]any{"code": "conflict", "error": "Hysteria 2 settings changed; prepare the change again"})
		return
	}
	node, err := s.store.GetSettings(r.Context())
	if err != nil {
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusConflict, map[string]any{"code": "settings_incomplete", "error": "Xray settings are incomplete"})
		return
	}
	manager := backup.NewManager(s.store, s.dataDir, s.configDir, s.masterKey)
	backupInfo, err := manager.Create("hysteria-settings")
	if err != nil {
		s.recordDiagnostic("error", "automatic Hysteria 2 backup failed: "+err.Error())
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "backup_failed", "error": "could not create automatic backup"})
		return
	}
	privateKey, err := secret.Open(s.masterKey, node.RealityPrivateKeyEnc, "reality_private_key")
	if err != nil {
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not decrypt REALITY private key"})
		return
	}
	clients, err := s.store.ListClients(r.Context())
	if err != nil {
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not list profiles"})
		return
	}
	reserved, err := s.store.ListReservedShortIDs(r.Context())
	if err != nil {
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not read REALITY short IDs"})
		return
	}
	path, operationID, err := s.prepareCandidateWithHysteriaLocked(r.Context(), node, privateKey, clients, reserved, pending.Candidate)
	if err != nil {
		s.recordDiagnostic("error", "Hysteria 2 candidate validation failed: "+err.Error())
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusBadGateway, map[string]any{"code": "apply_failed", "error": "Xray rejected the Hysteria 2 configuration"})
		return
	}
	activePath := filepath.Join(s.configDir, "active.json")
	oldHasInbound := hasInboundTag(activePath, xray.HysteriaInboundTag)
	oldHasVMessInbound := hasInboundTag(activePath, xray.VMessInboundTag)
	vmessExpected := vmessInboundExpected(clients)
	changeVMessTLS := (vmessExpected || oldHasVMessInbound) && (vmessCertificateChanged(current, pending.Candidate) || (!oldHasVMessInbound && vmessExpected))
	changeHysteria := oldHasInbound || pending.Candidate.Enabled
	runtimeTags := make([]string, 0, 2)
	if changeHysteria {
		runtimeTags = append(runtimeTags, xray.HysteriaInboundTag)
	}
	if changeVMessTLS {
		runtimeTags = append(runtimeTags, xray.VMessInboundTag)
	}
	needsRuntimeChange := len(runtimeTags) > 0
	if err := s.store.UpdateApplyOperation(r.Context(), operationID, "applying", ""); err != nil {
		_ = os.Remove(path)
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "apply_failed", "error": "could not record apply operation"})
		return
	}
	replacedTags := make([]string, 0, len(runtimeTags))
	var replacer inboundReplacer
	if needsRuntimeChange {
		var ok bool
		replacer, ok = s.supervisor.(inboundReplacer)
		if !ok {
			_ = os.Remove(path)
			_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", "inbound replacement is unavailable")
			s.finishHysteriaChange(request.ChangeID, false)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "apply_failed", "error": "Xray inbound replacement is unavailable"})
			return
		}
		for _, tag := range runtimeTags {
			if err := replacer.ReplaceInbound(r.Context(), path, activePath, tag, operationID); err != nil {
				for i := len(replacedTags) - 1; i >= 0; i-- {
					_ = replacer.ReplaceInbound(r.Context(), activePath, path, replacedTags[i], operationID+"-rollback")
				}
				_ = os.Remove(path)
				_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", err.Error())
				s.recordDiagnostic("error", tag+" inbound apply failed: "+err.Error())
				s.finishHysteriaChange(request.ChangeID, false)
				writeJSON(w, http.StatusBadGateway, map[string]any{"code": "apply_failed", "error": "could not update Xray inbound; previous state was restored"})
				return
			}
			replacedTags = append(replacedTags, tag)
		}
	}
	if err := s.store.UpdateHysteriaSettings(r.Context(), pending.Candidate); err != nil {
		for i := len(replacedTags) - 1; i >= 0; i-- {
			_ = replacer.ReplaceInbound(r.Context(), activePath, path, replacedTags[i], operationID+"-rollback")
		}
		_ = os.Remove(path)
		_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", err.Error())
		s.finishHysteriaChange(request.ChangeID, false)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "apply_failed", "error": "could not persist Hysteria 2 settings"})
		return
	}
	if needsRuntimeChange {
		if err := os.Rename(path, activePath); err != nil {
			_ = s.store.UpdateHysteriaSettings(r.Context(), current)
			for i := len(replacedTags) - 1; i >= 0; i-- {
				_ = replacer.ReplaceInbound(r.Context(), activePath, path, replacedTags[i], operationID+"-rollback")
			}
			_ = s.store.UpdateApplyOperation(r.Context(), operationID, "failed", err.Error())
			s.finishHysteriaChange(request.ChangeID, false)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "apply_failed", "error": "could not promote Xray configuration"})
			return
		}
	} else {
		_ = os.Remove(path)
	}
	_ = s.store.UpdateApplyOperation(r.Context(), operationID, "committed", "")
	_ = s.store.AddAudit(r.Context(), admin.ID, "hysteria.settings.apply", "hysteria_settings", "node", fmt.Sprintf("Hysteria 2 settings applied; enabled=%t; backup=%s", pending.Candidate.Enabled, backupInfo.Name))
	s.finishHysteriaChange(request.ChangeID, true)
	s.notifyEvents()
	status, _ := s.hysteriaSettingsStatus(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"applied": true, "settings": status, "backup": backupInfo.Name})
}

func (s *server) finishHysteriaChange(id string, applied bool) {
	s.hysteriaMu.Lock()
	defer s.hysteriaMu.Unlock()
	if applied {
		delete(s.pendingHysteria, id)
		return
	}
	if pending, ok := s.pendingHysteria[id]; ok {
		pending.Applying = false
		s.pendingHysteria[id] = pending
	}
}

func (s *server) hysteriaPublicSettings(settings domain.HysteriaSettings, node domain.Settings, certificate *hysteria.CertificateInfo) hysteriaSettingsResponse {
	host := settings.Host
	if host == "" {
		host = node.PublicHost
	}
	return hysteriaSettingsResponse{
		Enabled: settings.Enabled, State: "ready", Host: host, UDPPort: s.publicPort,
		TLSMode: settings.TLSMode, TLSServerName: settings.EffectiveTLSServerName(node.PublicHost),
		TLSCertIP: settings.TLSCertIP, CertificateID: settings.CertificateID,
		Certificate: certificate, UDPIdleTimeout: settings.UDPIdleTimeout,
		MasqueradeType: settings.MasqueradeType, MasqueradeString: settings.MasqueradeString,
		InsecureURI: settings.TLSMode == domain.HysteriaTLSSelfSigned || settings.TLSMode == domain.HysteriaTLSLegacy,
	}
}

func (s *server) hysteriaTLSDir() string {
	return filepath.Join(s.dataDir, "hysteria-tls")
}

func (s *server) lockHysteriaStorage(ctx context.Context) (func(), error) {
	s.applyMu.Lock()
	lock, err := maintenance.Acquire(ctx, s.maintenancePath)
	if err != nil {
		s.applyMu.Unlock()
		return nil, err
	}
	return func() {
		_ = lock.Close()
		s.applyMu.Unlock()
	}, nil
}
