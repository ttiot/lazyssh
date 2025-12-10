package ssh_config_file

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Adembc/lazyssh/internal/core/domain"
	"go.uber.org/zap"
)

func TestListServersIncludesNestedFiles(t *testing.T) {
	tempDir := t.TempDir()
	logger := zap.NewNop().Sugar()

	includeDir := filepath.Join(tempDir, "conf.d")
	if err := os.MkdirAll(includeDir, 0o755); err != nil {
		t.Fatalf("failed to create include dir: %v", err)
	}

	nestedDir := filepath.Join(includeDir, "nested")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		t.Fatalf("failed to create nested dir: %v", err)
	}

	includeFile := filepath.Join(includeDir, "included.conf")
	nestedInclude := filepath.Join(nestedDir, "nested.conf")

	if err := os.WriteFile(includeFile, []byte("Include "+nestedInclude+"\nHost include-host\n  HostName include.example.com\n"), 0o600); err != nil {
		t.Fatalf("failed to write include file: %v", err)
	}

	if err := os.WriteFile(nestedInclude, []byte("Host nested-host\n  HostName nested.example.com\n"), 0o600); err != nil {
		t.Fatalf("failed to write nested include file: %v", err)
	}

	mainConfig := filepath.Join(tempDir, "config")
	includePattern := filepath.Join(includeDir, "*.conf")
	configContent := "Include " + includePattern + "\nHost base-host\n  HostName base.example.com\n"
	if err := os.WriteFile(mainConfig, []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write main config: %v", err)
	}

	repo := &Repository{
		logger:          logger,
		configPath:      mainConfig,
		fileSystem:      DefaultFileSystem{},
		metadataManager: newMetadataManager(filepath.Join(tempDir, "metadata.json"), logger),
	}

	servers, err := repo.ListServers("")
	if err != nil {
		t.Fatalf("ListServers returned error: %v", err)
	}

	gotAliases := map[string]bool{}
	for _, s := range servers {
		gotAliases[s.Alias] = true
	}

	for _, alias := range []string{"base-host", "include-host", "nested-host"} {
		if !gotAliases[alias] {
			t.Fatalf("expected alias %s to be parsed from includes", alias)
		}
	}
}

func TestAddServerDetectsAliasInIncludedConfig(t *testing.T) {
	tempDir := t.TempDir()
	logger := zap.NewNop().Sugar()

	includeFile := filepath.Join(tempDir, "included.conf")
	if err := os.WriteFile(includeFile, []byte("Host existing\n  HostName include.example.com\n"), 0o600); err != nil {
		t.Fatalf("failed to write include file: %v", err)
	}

	mainConfig := filepath.Join(tempDir, "config")
	configContent := "Include " + includeFile + "\n"
	if err := os.WriteFile(mainConfig, []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write main config: %v", err)
	}

	repo := &Repository{
		logger:          logger,
		configPath:      mainConfig,
		fileSystem:      DefaultFileSystem{},
		metadataManager: newMetadataManager(filepath.Join(tempDir, "metadata.json"), logger),
	}

	err := repo.AddServer(domain.Server{Alias: "existing", Host: "new.example.com", User: "me"})
	if err == nil {
		t.Fatalf("expected AddServer to fail due to existing alias in includes")
	}
}
