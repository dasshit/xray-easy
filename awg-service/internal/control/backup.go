package control

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	awgapi "xray-easy/awg-contract/api/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const maxAWGBackupSize = 16 << 20

// ExportBackup returns a gzip-compressed tar archive of AWG state and private
// client profiles. The control-plane backup manager wraps this file in its
// authenticated manifest; the archive remains plaintext by product design.
func (s *Service) ExportBackup(context.Context, *emptypb.Empty) (*awgapi.BackupResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	archive, err := createAWGBackup(s.options.DataDir, s.manager)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "export AmneziaWG backup: %v", err)
	}
	return &awgapi.BackupResponse{Data: archive}, nil
}

// RestoreBackup validates and applies a complete state/profile archive. The
// AWG interface and persistent state are restored together without restarting
// the service container.
func (s *Service) RestoreBackup(_ context.Context, request *awgapi.RestoreBackupRequest) (*awgapi.RestoreBackupResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	archive := request.GetData()
	if len(archive) > maxAWGBackupSize {
		return nil, status.Error(codes.InvalidArgument, "AmneziaWG backup exceeds the size limit")
	}
	if err := restoreAWGBackup(s.options.DataDir, s.manager, archive); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "restore AmneziaWG backup: %v", err)
	}
	return &awgapi.RestoreBackupResponse{Restored: true}, nil
}

func createAWGBackup(dataDir string, manager *Manager) ([]byte, error) {
	if manager == nil || strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("AmneziaWG service is not initialized")
	}
	statePath := filepath.Join(dataDir, "state.json")
	stateInfo, err := os.Lstat(statePath)
	if err != nil || !stateInfo.Mode().IsRegular() {
		return nil, errors.New("persistent state is missing or is not a regular file")
	}
	state, err := readState(statePath)
	if err != nil {
		return nil, fmt.Errorf("read persistent state: %w", err)
	}
	if err := validateState(state, manager.opts); err != nil {
		return nil, err
	}
	if _, err := openPrivateKey(state.PrivateKeyEnvelope, manager.opts.MasterKey); err != nil {
		return nil, fmt.Errorf("verify encrypted server key: %w", err)
	}

	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) error {
		if int64(len(data)) > maxAWGBackupSize {
			return errors.New("AmneziaWG backup exceeds the size limit")
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		return nil, err
	}
	if err := write("state.json", stateData); err != nil {
		return nil, err
	}
	profileDir := filepath.Join(dataDir, "profiles")
	profileInfo, profileStatErr := os.Lstat(profileDir)
	if profileStatErr == nil && (!profileInfo.IsDir() || profileInfo.Mode()&os.ModeSymlink != 0) {
		return nil, errors.New("saved client profile path must be a directory")
	}
	if profileStatErr != nil && !os.IsNotExist(profileStatErr) {
		return nil, profileStatErr
	}
	entries, err := os.ReadDir(profileDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	profileNames := make(map[string]bool, len(entries))
	var total int64 = int64(len(stateData))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || !servicePeerNamePattern.MatchString(strings.TrimSuffix(entry.Name(), ".conf")) || filepath.Ext(entry.Name()) != ".conf" {
			return nil, fmt.Errorf("unsupported entry in saved AmneziaWG profiles: %s", entry.Name())
		}
		name := strings.TrimSuffix(entry.Name(), ".conf")
		if profileNames[name] {
			return nil, fmt.Errorf("duplicate saved profile for peer %q", name)
		}
		profileNames[name] = true
		path := filepath.Join(profileDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maxAWGBackupSize {
			return nil, fmt.Errorf("saved profile %q is missing, too large, or has unsafe permissions", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if !profileMatchesPeer(name, data, state.Peers) {
			return nil, fmt.Errorf("saved profile %q does not match a configured peer", name)
		}
		total += int64(len(data))
		if total > maxAWGBackupSize {
			return nil, errors.New("AmneziaWG backup exceeds the size limit")
		}
		if err := write("profiles/"+entry.Name(), data); err != nil {
			return nil, err
		}
	}
	for _, peer := range state.Peers {
		if !profileNames[peer.Name] {
			return nil, fmt.Errorf("saved client profile for peer %q is missing; refresh the profile before creating a backup", peer.Name)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if compressed.Len() > maxAWGBackupSize {
		return nil, errors.New("AmneziaWG backup exceeds the size limit")
	}
	return compressed.Bytes(), nil
}

func restoreAWGBackup(dataDir string, manager *Manager, archive []byte) error {
	if manager == nil || strings.TrimSpace(dataDir) == "" {
		return errors.New("AmneziaWG service is not initialized")
	}
	stageRoot, err := os.MkdirTemp(dataDir, ".restore-awg-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stageRoot)
	stageProfiles := filepath.Join(stageRoot, "profiles")
	if err := os.Mkdir(stageProfiles, 0700); err != nil {
		return err
	}
	stateData, err := extractAWGBackup(stageRoot, archive)
	if err != nil {
		return err
	}
	state, err := readSnapshotState(stateData, manager.opts)
	if err != nil {
		return err
	}
	profiles, err := os.ReadDir(stageProfiles)
	if err != nil {
		return err
	}
	if len(profiles) != len(state.Peers) {
		return errors.New("backup does not contain exactly one client profile for every peer")
	}
	for _, entry := range profiles {
		name := strings.TrimSuffix(entry.Name(), ".conf")
		data, err := os.ReadFile(filepath.Join(stageProfiles, entry.Name()))
		if err != nil || !profileMatchesPeer(name, data, state.Peers) {
			return fmt.Errorf("profile %q is invalid or does not match a restored peer", name)
		}
	}

	profileRoot := filepath.Join(dataDir, "profiles")
	previousProfiles := filepath.Join(stageRoot, "previous-profiles")
	hadPreviousProfiles := false
	if _, err := os.Lstat(profileRoot); err == nil {
		if err := os.Rename(profileRoot, previousProfiles); err != nil {
			return fmt.Errorf("stage existing client profiles: %w", err)
		}
		hadPreviousProfiles = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(stageProfiles, profileRoot); err != nil {
		if hadPreviousProfiles {
			_ = os.Rename(previousProfiles, profileRoot)
		}
		return fmt.Errorf("install restored client profiles: %w", err)
	}
	if err := manager.RestorePersistedState(stateData); err != nil {
		_ = os.RemoveAll(profileRoot)
		if hadPreviousProfiles {
			_ = os.Rename(previousProfiles, profileRoot)
		}
		return err
	}
	return nil
}

func extractAWGBackup(root string, archive []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxAWGBackupSize+1))
	var state []byte
	var total int64
	seen := make(map[string]bool)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read archive: %w", err)
		}
		name := filepath.ToSlash(filepath.Clean(filepath.FromSlash(header.Name)))
		if name != header.Name || strings.HasPrefix(name, "../") || filepath.IsAbs(name) || seen[name] {
			return nil, errors.New("archive contains an unsafe or duplicate path")
		}
		if header.Typeflag == tar.TypeDir && name == "profiles" {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > maxAWGBackupSize {
			return nil, errors.New("archive contains an unsupported entry")
		}
		validState := name == "state.json"
		profileName := ""
		if strings.HasPrefix(name, "profiles/") && strings.HasSuffix(name, ".conf") {
			profileName = strings.TrimSuffix(strings.TrimPrefix(name, "profiles/"), ".conf")
		}
		if !validState && (profileName == "" || strings.Contains(profileName, "/") || !servicePeerNamePattern.MatchString(profileName)) {
			return nil, errors.New("archive contains an unexpected file")
		}
		total += header.Size
		if total > maxAWGBackupSize {
			return nil, errors.New("archive exceeds the expanded size limit")
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if !validState {
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return nil, err
			}
		}
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(tr, header.Size+1))
		if readErr == nil && int64(len(data)) != header.Size {
			readErr = errors.New("archive entry size does not match its header")
		}
		if readErr == nil {
			_, readErr = file.Write(data)
		}
		closeErr := file.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		seen[name] = true
		if validState {
			state = data
		}
	}
	if len(state) == 0 {
		return nil, errors.New("archive has no state.json")
	}
	return state, nil
}

func readSnapshotState(data []byte, opts Options) (persistedState, error) {
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return persistedState{}, fmt.Errorf("decode state.json: %w", err)
	}
	if state.Peers == nil {
		state.Peers = []Peer{}
	}
	if err := validateState(state, opts); err != nil {
		return persistedState{}, err
	}
	if _, err := openPrivateKey(state.PrivateKeyEnvelope, opts.MasterKey); err != nil {
		return persistedState{}, fmt.Errorf("decrypt server key: %w", err)
	}
	return state, nil
}

func profileMatchesPeer(name string, data []byte, peers []Peer) bool {
	privateKey, err := privateKeyFromProfile(string(data))
	if err != nil {
		return false
	}
	_, publicKey, err := derivePublicKey(privateKey)
	if err != nil {
		return false
	}
	for _, peer := range peers {
		if peer.Name == name {
			return peer.PublicKey == publicKey
		}
	}
	return false
}
