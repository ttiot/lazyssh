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
	"os"
	"path/filepath"
	"reflect"
	"time"
	"unsafe"

	"github.com/kevinburke/ssh_config"
)

// loadConfig reads and parses the SSH config file.
// If the file does not exist, it returns an empty config without error to support first-run behavior.
func (r *Repository) loadConfig() (*ssh_config.Config, error) {
	file, err := r.fileSystem.Open(r.configPath)
	if err != nil {
		if r.fileSystem.IsNotExist(err) {
			return &ssh_config.Config{Hosts: []*ssh_config.Host{}}, nil
		}
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			r.logger.Warnf("failed to close config file: %v", cerr)
		}
	}()

	cfg, err := ssh_config.Decode(file)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return cfg, nil
}

// loadConfigWithIncludes returns the base SSH config along with all hosts from included files.
func (r *Repository) loadConfigWithIncludes() (*ssh_config.Config, []*ssh_config.Host, error) {
	cfg, err := r.loadConfig()
	if err != nil {
		return nil, nil, err
	}

	visited := map[string]bool{filepath.Clean(r.configPath): true}
	hosts := r.collectHosts(cfg, visited)

	return cfg, hosts, nil
}

// collectHosts gathers hosts from the given config and any nested Include directives.
func (r *Repository) collectHosts(cfg *ssh_config.Config, visited map[string]bool) []*ssh_config.Host {
	hosts := make([]*ssh_config.Host, 0, len(cfg.Hosts))

	for _, host := range cfg.Hosts {
		hosts = append(hosts, host)
		hosts = append(hosts, r.collectHostsFromNodes(host.Nodes, visited)...)
	}

	return hosts
}

// collectHostsFromNodes recursively collects hosts referenced by Include directives within the provided nodes.
func (r *Repository) collectHostsFromNodes(nodes []ssh_config.Node, visited map[string]bool) []*ssh_config.Host {
	includeHosts := make([]*ssh_config.Host, 0)

	for _, node := range nodes {
		includeNode, ok := node.(*ssh_config.Include)
		if !ok {
			continue
		}

		matches, files := r.extractIncludeDetails(includeNode)
		for _, match := range matches {
			if visited[match] {
				continue
			}

			visited[match] = true
			includedCfg, exists := files[match]
			if !exists || includedCfg == nil {
				r.logger.Warnf("include target %s missing or not parsed", match)
				continue
			}

			includeHosts = append(includeHosts, r.collectHosts(includedCfg, visited)...)
		}
	}

	return includeHosts
}

// extractIncludeDetails uses reflection to access the include matches and parsed configs.
// The underlying ssh_config.Include type keeps these fields unexported.
func (r *Repository) extractIncludeDetails(includeNode *ssh_config.Include) ([]string, map[string]*ssh_config.Config) {
	includeValue := reflect.ValueOf(includeNode).Elem()

	matchesValue := includeValue.FieldByName("matches")
	filesValue := includeValue.FieldByName("files")

	matches := []string{}
	files := map[string]*ssh_config.Config{}

	if matchesValue.IsValid() {
		//nolint:gosec // Accessing unexported matches field is required because ssh_config.Include does not expose accessors.
		matchesPtr := reflect.NewAt(matchesValue.Type(), unsafe.Pointer(matchesValue.UnsafeAddr())).Elem()
		if m, ok := matchesPtr.Interface().([]string); ok {
			matches = m
		}
	}

	if filesValue.IsValid() {
		//nolint:gosec // Accessing unexported files field is required because ssh_config.Include does not expose accessors.
		filesPtr := reflect.NewAt(filesValue.Type(), unsafe.Pointer(filesValue.UnsafeAddr())).Elem()
		if f, ok := filesPtr.Interface().(map[string]*ssh_config.Config); ok {
			files = f
		}
	}

	return matches, files
}

// saveConfig writes the SSH config back to the file with atomic operations and backup management.
func (r *Repository) saveConfig(cfg *ssh_config.Config) error {
	configDir := filepath.Dir(r.configPath)

	tempFile, err := r.createTempFile(configDir)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	defer func() {
		if removeErr := r.fileSystem.Remove(tempFile); removeErr != nil {
			r.logger.Warnf("failed to remove temporary file %s: %v", tempFile, removeErr)
		}
	}()

	if err := r.writeConfigToFile(tempFile, cfg); err != nil {
		return fmt.Errorf("failed to write config to temporary file: %w", err)
	}

	// Ensure a one-time original backup exists before any modifications managed by lazyssh.
	if err := r.createOriginalBackupIfNeeded(); err != nil {
		return fmt.Errorf("failed to create original backup: %w", err)
	}

	if err := r.createBackup(); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}

	if err := r.fileSystem.Rename(tempFile, r.configPath); err != nil {
		return fmt.Errorf("failed to atomically replace config file: %w", err)
	}

	r.logger.Infof("SSH config successfully updated: %s", r.configPath)
	return nil
}

// writeConfigToFile writes the SSH config content to the specified file
func (r *Repository) writeConfigToFile(filePath string, cfg *ssh_config.Config) error {
	file, err := r.fileSystem.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, SSHConfigPerms)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			r.logger.Warnf("failed to close file %s: %v", filePath, cerr)
		}
	}()

	configContent := cfg.String()
	if _, err := file.WriteString(configContent); err != nil {
		return fmt.Errorf("failed to write config content: %w", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file to disk: %w", err)
	}

	return nil
}

// createTempFile creates a temporary file in the specified directory
func (r *Repository) createTempFile(dir string) (string, error) {
	timestamp := time.Now().Format("20060102150405")
	tempFileName := fmt.Sprintf("config%s%s", timestamp, TempSuffix)
	tempFilePath := filepath.Join(dir, tempFileName)

	// Create the temp file with explicit 0600 permissions
	f, err := r.fileSystem.OpenFile(tempFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, SSHConfigPerms)
	if err != nil {
		return "", err
	}
	if cerr := f.Close(); cerr != nil {
		r.logger.Warnf("failed to close temporary file %s: %v", tempFilePath, cerr)
	}

	return tempFilePath, nil
}
