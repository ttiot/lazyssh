// Copyright 2025.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ssh_config_file

import (
	"fmt"
	"sync"

	"github.com/Adembc/lazyssh/internal/core/domain"
	"github.com/Adembc/lazyssh/internal/core/ports"
	"github.com/kevinburke/ssh_config"
	"go.uber.org/zap"
)

// Repository implements ServerRepository interface for SSH config file operations.
type Repository struct {
	configPath      string
	fileSystem      FileSystem
	metadataManager *metadataManager
	logger          *zap.SugaredLogger

	cacheMu       sync.RWMutex
	cachedServers []domain.Server
}

// NewRepository creates a new SSH config repository.
func NewRepository(logger *zap.SugaredLogger, configPath, metaDataPath string) ports.ServerRepository {
	return &Repository{
		logger:          logger,
		configPath:      configPath,
		fileSystem:      DefaultFileSystem{},
		metadataManager: newMetadataManager(metaDataPath, logger),
	}
}

// NewRepositoryWithFS creates a new SSH config repository with a custom filesystem.
func NewRepositoryWithFS(logger *zap.SugaredLogger, configPath string, metaDataPath string, fs FileSystem) ports.ServerRepository {
	return &Repository{
		logger:          logger,
		configPath:      configPath,
		fileSystem:      fs,
		metadataManager: newMetadataManager(metaDataPath, logger),
	}
}

// ListServers returns all servers matching the query pattern.
// Empty query returns all servers.
func (r *Repository) ListServers(query string) ([]domain.Server, error) {
	servers, err := r.getOrLoadServers()
	if err != nil {
		return nil, err
	}

	if query == "" {
		return servers, nil
	}

	return r.filterServers(servers, query), nil
}

func (r *Repository) getOrLoadServers() ([]domain.Server, error) {
	r.cacheMu.RLock()
	if r.cachedServers != nil {
		deferredCopy := cloneServers(r.cachedServers)
		r.cacheMu.RUnlock()
		return deferredCopy, nil
	}
	r.cacheMu.RUnlock()

	_, hosts, err := r.loadConfigWithIncludes()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	servers := r.toDomainServer(hosts)
	metadata, err := r.metadataManager.loadAll()
	if err != nil {
		r.logger.Warnf("Failed to load metadata: %v", err)
		metadata = make(map[string]ServerMetadata)
	}
	servers = r.mergeMetadata(servers, metadata)

	r.cacheMu.Lock()
	r.cachedServers = servers
	r.cacheMu.Unlock()

	return cloneServers(servers), nil
}

func (r *Repository) invalidateCache() {
	r.cacheMu.Lock()
	r.cachedServers = nil
	r.cacheMu.Unlock()
}

func cloneServers(servers []domain.Server) []domain.Server {
	cloned := make([]domain.Server, len(servers))
	for i, srv := range servers {
		cloned[i] = cloneServer(srv)
	}
	return cloned
}

func cloneServer(s domain.Server) domain.Server {
	return domain.Server{
		Alias:                        s.Alias,
		Aliases:                      cloneStringSlice(s.Aliases),
		Host:                         s.Host,
		User:                         s.User,
		Port:                         s.Port,
		IdentityFiles:                cloneStringSlice(s.IdentityFiles),
		Tags:                         cloneStringSlice(s.Tags),
		LastSeen:                     s.LastSeen,
		PinnedAt:                     s.PinnedAt,
		SSHCount:                     s.SSHCount,
		ProxyJump:                    s.ProxyJump,
		ProxyCommand:                 s.ProxyCommand,
		RemoteCommand:                s.RemoteCommand,
		RequestTTY:                   s.RequestTTY,
		SessionType:                  s.SessionType,
		ConnectTimeout:               s.ConnectTimeout,
		ConnectionAttempts:           s.ConnectionAttempts,
		BindAddress:                  s.BindAddress,
		BindInterface:                s.BindInterface,
		AddressFamily:                s.AddressFamily,
		ExitOnForwardFailure:         s.ExitOnForwardFailure,
		IPQoS:                        s.IPQoS,
		CanonicalizeHostname:         s.CanonicalizeHostname,
		CanonicalDomains:             s.CanonicalDomains,
		CanonicalizeFallbackLocal:    s.CanonicalizeFallbackLocal,
		CanonicalizeMaxDots:          s.CanonicalizeMaxDots,
		CanonicalizePermittedCNAMEs:  s.CanonicalizePermittedCNAMEs,
		LocalForward:                 cloneStringSlice(s.LocalForward),
		RemoteForward:                cloneStringSlice(s.RemoteForward),
		DynamicForward:               cloneStringSlice(s.DynamicForward),
		ClearAllForwardings:          s.ClearAllForwardings,
		GatewayPorts:                 s.GatewayPorts,
		PubkeyAuthentication:         s.PubkeyAuthentication,
		PubkeyAcceptedAlgorithms:     s.PubkeyAcceptedAlgorithms,
		HostbasedAcceptedAlgorithms:  s.HostbasedAcceptedAlgorithms,
		IdentitiesOnly:               s.IdentitiesOnly,
		AddKeysToAgent:               s.AddKeysToAgent,
		IdentityAgent:                s.IdentityAgent,
		PasswordAuthentication:       s.PasswordAuthentication,
		KbdInteractiveAuthentication: s.KbdInteractiveAuthentication,
		NumberOfPasswordPrompts:      s.NumberOfPasswordPrompts,
		PreferredAuthentications:     s.PreferredAuthentications,
		ForwardAgent:                 s.ForwardAgent,
		ForwardX11:                   s.ForwardX11,
		ForwardX11Trusted:            s.ForwardX11Trusted,
		ControlMaster:                s.ControlMaster,
		ControlPath:                  s.ControlPath,
		ControlPersist:               s.ControlPersist,
		ServerAliveInterval:          s.ServerAliveInterval,
		ServerAliveCountMax:          s.ServerAliveCountMax,
		Compression:                  s.Compression,
		TCPKeepAlive:                 s.TCPKeepAlive,
		BatchMode:                    s.BatchMode,
		StrictHostKeyChecking:        s.StrictHostKeyChecking,
		CheckHostIP:                  s.CheckHostIP,
		FingerprintHash:              s.FingerprintHash,
		UserKnownHostsFile:           s.UserKnownHostsFile,
		HostKeyAlgorithms:            s.HostKeyAlgorithms,
		MACs:                         s.MACs,
		Ciphers:                      s.Ciphers,
		KexAlgorithms:                s.KexAlgorithms,
		VerifyHostKeyDNS:             s.VerifyHostKeyDNS,
		UpdateHostKeys:               s.UpdateHostKeys,
		HashKnownHosts:               s.HashKnownHosts,
		VisualHostKey:                s.VisualHostKey,
		LocalCommand:                 s.LocalCommand,
		PermitLocalCommand:           s.PermitLocalCommand,
		EscapeChar:                   s.EscapeChar,
		SendEnv:                      cloneStringSlice(s.SendEnv),
		SetEnv:                       cloneStringSlice(s.SetEnv),
		LogLevel:                     s.LogLevel,
	}
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

// AddServer adds a new server to the SSH config.
func (r *Repository) AddServer(server domain.Server) error {
	cfg, hosts, err := r.loadConfigWithIncludes()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if r.serverExistsInHosts(hosts, server.Alias) {
		return fmt.Errorf("server with alias '%s' already exists", server.Alias)
	}

	host := r.createHostFromServer(server)
	cfg.Hosts = append(cfg.Hosts, host)

	if err := r.saveConfig(cfg); err != nil {
		r.logger.Warnf("Failed to save config while adding new server: %v", err)
		return fmt.Errorf("failed to save config: %w", err)
	}
	if err := r.metadataManager.updateServer(server, server.Alias); err != nil {
		return err
	}

	r.invalidateCache()
	return nil
}

// UpdateServer updates an existing server in the SSH config.
func (r *Repository) UpdateServer(server domain.Server, newServer domain.Server) error {
	cfg, hosts, err := r.loadConfigWithIncludes()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	host := r.findHostByAlias(cfg, server.Alias)
	if host == nil {
		return fmt.Errorf("server with alias '%s' not found", server.Alias)
	}

	if server.Alias != newServer.Alias {
		if r.serverExistsInHosts(hosts, newServer.Alias) {
			return fmt.Errorf("server with alias '%s' already exists", newServer.Alias)
		}

		newPatterns := make([]*ssh_config.Pattern, 0, len(host.Patterns))
		for _, pattern := range host.Patterns {
			if pattern.Str == server.Alias {
				newPatterns = append(newPatterns, &ssh_config.Pattern{Str: newServer.Alias})
			} else {
				newPatterns = append(newPatterns, pattern)
			}
		}

		host.Patterns = newPatterns

	}

	r.updateHostNodes(host, newServer)

	if err := r.saveConfig(cfg); err != nil {
		r.logger.Warnf("Failed to save config while updating server: %v", err)
		return fmt.Errorf("failed to save config: %w", err)
	}
	// Update metadata; pass old alias to allow inline migration
	if err := r.metadataManager.updateServer(newServer, server.Alias); err != nil {
		return err
	}

	r.invalidateCache()
	return nil
}

// DeleteServer removes a server from the SSH config.
func (r *Repository) DeleteServer(server domain.Server) error {
	cfg, err := r.loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	initialCount := len(cfg.Hosts)
	cfg.Hosts = r.removeHostByAlias(cfg.Hosts, server.Alias)

	if len(cfg.Hosts) == initialCount {
		return fmt.Errorf("server with alias '%s' not found", server.Alias)
	}

	if err := r.saveConfig(cfg); err != nil {
		r.logger.Warnf("Failed to save config while deleting server: %v", err)
		return fmt.Errorf("failed to save config: %w", err)
	}
	if err := r.metadataManager.deleteServer(server.Alias); err != nil {
		return err
	}

	r.invalidateCache()
	return nil
}

// SetPinned sets or unsets the pinned status of a server.
func (r *Repository) SetPinned(alias string, pinned bool) error {
	if err := r.metadataManager.setPinned(alias, pinned); err != nil {
		return err
	}

	r.invalidateCache()
	return nil
}

// RecordSSH increments the SSH access count and updates the last seen timestamp for a server.
func (r *Repository) RecordSSH(alias string) error {
	if err := r.metadataManager.recordSSH(alias); err != nil {
		return err
	}

	r.invalidateCache()
	return nil
}
