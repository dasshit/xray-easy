package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"xray-easy/internal/domain"
	"xray-easy/internal/maintenance"
	"xray-easy/internal/stats"
	"xray-easy/internal/store"

	"github.com/skip2/go-qrcode"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type amneziaWGStatusResponse struct {
	Enabled        bool   `json:"enabled"`
	Available      bool   `json:"available"`
	Running        bool   `json:"running"`
	PublicKey      string `json:"public_key,omitempty"`
	ListenPort     int    `json:"listen_port,omitempty"`
	PublicHost     string `json:"public_host,omitempty"`
	PublicPort     int    `json:"public_port,omitempty"`
	PeerCount      int    `json:"peer_count,omitempty"`
	IPv4Network    string `json:"ipv4_network,omitempty"`
	IPv6Network    string `json:"ipv6_network,omitempty"`
	ServiceVersion string `json:"service_version,omitempty"`
	Error          string `json:"error,omitempty"`
}

type amneziaWGPeerResponse struct {
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	IPv4      string    `json:"ipv4"`
	IPv6      string    `json:"ipv6"`
	CreatedAt time.Time `json:"created_at"`
}

type amneziaWGCreatePeerRequest struct {
	Name string `json:"name"`
}

func (s *server) amneziaWGStatus(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/transports/amneziawg" {
		http.NotFound(w, r)
		return
	}
	if _, err := s.authenticated(r); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, nil)
		return
	}
	if s.awg == nil {
		writeJSON(w, http.StatusOK, amneziaWGStatusResponse{Available: false})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	status, err := s.awg.Status(ctx)
	if err != nil {
		writeAWGError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, amneziaWGStatusResponse{
		Enabled: true, Available: true, Running: status.Running,
		PublicKey: status.PublicKey, ListenPort: status.ListenPort, PublicHost: status.PublicHost,
		PublicPort: status.PublicPort, PeerCount: status.PeerCount, IPv4Network: status.IPv4Network,
		IPv6Network: status.IPv6Network, ServiceVersion: status.ServiceVersion,
	})
}

func (s *server) amneziaWGPeers(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if s.awg == nil {
		writeAWGUnavailable(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		peers, err := s.awg.ListPeers(ctx)
		if err != nil {
			writeAWGError(w, err)
			return
		}
		items := make([]amneziaWGPeerResponse, 0, len(peers))
		for _, peer := range peers {
			items = append(items, mapAmneziaWGPeer(peer))
		}
		writeJSON(w, http.StatusOK, map[string]any{"peers": items})
	case http.MethodPost:
		lock, err := maintenance.Acquire(ctx, s.maintenancePath)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "maintenance lock is unavailable"})
			return
		}
		defer lock.Close()
		var request amneziaWGCreatePeerRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
			return
		}
		if err := domain.ValidateAmneziaWGPeerName(request.Name); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
			return
		}
		peer, err := s.awg.CreatePeer(ctx, request.Name)
		if err != nil {
			writeAWGError(w, err)
			return
		}
		_ = s.store.AddAudit(ctx, admin.ID, "awg.peer.create", "awg_peer", peer.Name, "created AmneziaWG peer; assigned IPv4 and IPv6 addresses")
		writeJSON(w, http.StatusCreated, mapAmneziaWGPeer(peer))
	default:
		writeJSON(w, http.StatusMethodNotAllowed, nil)
	}
}

func (s *server) createAWGClient(w http.ResponseWriter, r *http.Request, admin store.Admin, name, fingerprint, authValue string) {
	if fingerprint != "" || authValue != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "fingerprint and auth are not valid for AmneziaWG profiles"})
		return
	}
	if err := domain.ValidateAmneziaWGPeerName(name); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": err.Error()})
		return
	}
	if s.awg == nil {
		writeAWGUnavailable(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	status, err := s.awg.Status(ctx)
	if err != nil {
		writeAWGError(w, err)
		return
	}
	if !status.Running {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "service_unavailable", "error": "AmneziaWG service is not running"})
		return
	}
	lock, err := maintenance.Acquire(ctx, s.maintenancePath)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "maintenance lock is unavailable"})
		return
	}
	defer lock.Close()
	peer, err := s.awg.CreatePeer(ctx, name)
	if err != nil {
		writeAWGError(w, err)
		return
	}
	_ = s.store.AddAudit(ctx, admin.ID, "awg.peer.create", "awg_peer", peer.Name, "created AmneziaWG peer; assigned IPv4 and IPv6 addresses")
	writeJSON(w, http.StatusCreated, s.withAWGStats([]domain.AmneziaWGPeer{peer})[0])
}

func (s *server) withAWGStats(peers []domain.AmneziaWGPeer) []clientResponse {
	snapshot := map[string]stats.ClientStats{}
	if s.stats != nil {
		snapshot = s.stats.Snapshot()
	}
	result := make([]clientResponse, 0, len(peers))
	for _, peer := range peers {
		current := snapshot["awg:"+peer.Name]
		result = append(result, clientResponse{
			Protocol: domain.ProtocolAmneziaWG, Protocols: []string{string(domain.ProtocolAmneziaWG)},
			ID: "awg:" + peer.Name, Name: peer.Name, Enabled: true, CreatedAt: peer.CreatedAt, UpdatedAt: peer.CreatedAt,
			Online: current.Online, LastSeen: current.LastSeen, SourceIPs: current.SourceIPs,
			UploadBytes: current.UploadBytes, DownloadBytes: current.DownloadBytes,
			UploadRate: current.UploadBytesPerSecond, DownloadRate: current.DownloadBytesPerSecond,
		})
	}
	return result
}

// amneziaWGClientRoute adapts AWG peer lifecycle and credential delivery to the
// shared /api/clients/{id} resource while preserving the private AWG service as
// the owner of profile material.
func (s *server) amneziaWGClientRoute(w http.ResponseWriter, r *http.Request, _ store.Admin, parts []string, name string) {
	if err := domain.ValidateAmneziaWGPeerName(name); err != nil {
		http.NotFound(w, r)
		return
	}
	if s.awg == nil {
		writeAWGUnavailable(w)
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" && r.Method == http.MethodPost {
		proxy := r.Clone(r.Context())
		proxy.Method = http.MethodDelete
		proxy.URL.Path = "/api/transports/amneziawg/peers/" + name
		s.amneziaWGPeerRoute(w, proxy)
		return
	}
	if len(parts) != 2 || parts[1] != "profile" || r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"code": "method_not_allowed", "error": "AmneziaWG profiles support only delivery and revoke"})
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" || format == "uri" {
		peers, err := s.awg.ListPeers(r.Context())
		if err != nil {
			writeAWGError(w, err)
			return
		}
		for _, peer := range peers {
			if peer.Name == name {
				writeJSON(w, http.StatusOK, map[string]any{"client_id": "awg:" + name, "protocol": domain.ProtocolAmneziaWG, "name": name})
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]any{"code": "not_found", "error": "AmneziaWG peer not found"})
		return
	}
	path := "/api/transports/amneziawg/peers/" + name + "/profile"
	switch format {
	case "conf":
	case "qr":
		path += "/qr"
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "unsupported AmneziaWG profile format"})
		return
	}
	proxy := r.Clone(r.Context())
	proxy.URL.Path = path
	s.amneziaWGPeerRoute(w, proxy)
}

func (s *server) amneziaWGPeerRoute(w http.ResponseWriter, r *http.Request) {
	admin, err := s.authenticated(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	if s.awg == nil {
		writeAWGUnavailable(w)
		return
	}
	relative := strings.TrimPrefix(r.URL.Path, "/api/transports/amneziawg/peers/")
	parts := strings.Split(relative, "/")
	if len(parts) < 1 || parts[0] == "." || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	name := parts[0]
	if err := domain.ValidateAmneziaWGPeerName(name); err != nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if len(parts) == 1 && r.Method == http.MethodDelete {
		lock, err := maintenance.Acquire(ctx, s.maintenancePath)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "maintenance lock is unavailable"})
			return
		}
		defer lock.Close()
		peers, err := s.awg.ListPeers(ctx)
		if err != nil {
			writeAWGError(w, err)
			return
		}
		found := false
		for _, peer := range peers {
			found = found || peer.Name == name
		}
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "AmneziaWG peer not found"})
			return
		}
		manager := s.backupManager()
		backupInfo, err := manager.CreateContext(ctx, "awg-peer-revoke")
		if err != nil {
			s.recordDiagnostic("error", "automatic AmneziaWG revoke backup failed: "+err.Error())
			writeJSON(w, http.StatusInternalServerError, map[string]any{"code": "backup_failed", "error": "could not create automatic backup before revoking the peer"})
			return
		}
		if err := s.awg.RemovePeer(ctx, name); err != nil {
			writeAWGError(w, err)
			return
		}
		if err := s.store.DeleteAWGTrafficSnapshot(ctx, name); err != nil {
			s.recordDiagnostic("warn", "could not remove AmneziaWG traffic checkpoint: "+err.Error())
		}
		_ = s.store.AddAudit(ctx, admin.ID, "awg.peer.revoke", "awg_peer", name, "revoked AmneziaWG peer; automatic backup "+backupInfo.Name+" created")
		writeJSON(w, http.StatusOK, map[string]any{"removed": true, "name": name, "backup_name": backupInfo.Name})
		return
	}
	if len(parts) == 2 && parts[1] == "profile" && r.Method == http.MethodGet {
		profile, err := s.awg.ClientConfig(ctx, name)
		if err != nil {
			writeAWGError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/x-amneziawg-profile; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+".conf"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(profile))
		return
	}
	if len(parts) == 3 && parts[1] == "profile" && parts[2] == "qr" && r.Method == http.MethodGet {
		profile, err := s.awg.ClientConfig(ctx, name)
		if err != nil {
			writeAWGError(w, err)
			return
		}
		image, err := qrcode.Encode(profile, qrcode.Medium, 640)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "could not render AmneziaWG profile QR code"})
			return
		}
		w.Header().Set("Cache-Control", "no-store, private")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(image)
		return
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
}

func mapAmneziaWGPeer(peer domain.AmneziaWGPeer) amneziaWGPeerResponse {
	return amneziaWGPeerResponse{Name: peer.Name, PublicKey: peer.PublicKey, IPv4: peer.IPv4, IPv6: peer.IPv6, CreatedAt: peer.CreatedAt}
}

func writeAWGUnavailable(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "service_unavailable", "error": "AmneziaWG service is not configured; start the awg Compose profile"})
}

func writeAWGError(w http.ResponseWriter, err error) {
	switch status.Code(err) {
	case codes.InvalidArgument:
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "validation_error", "error": "invalid AmneziaWG request"})
	case codes.NotFound:
		writeJSON(w, http.StatusNotFound, map[string]any{"code": "not_found", "error": "AmneziaWG peer not found"})
	case codes.AlreadyExists:
		writeJSON(w, http.StatusConflict, map[string]any{"code": "already_exists", "error": "an AmneziaWG peer with this name already exists"})
	case codes.Unavailable, codes.DeadlineExceeded:
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "service_unavailable", "error": "AmneziaWG service is not running"})
	default:
		if err == nil {
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]any{"code": "upstream_error", "error": "AmneziaWG operation failed"})
	}
}
