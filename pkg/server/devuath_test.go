package server

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"go.uber.org/zap"
)

func TestResolveProxyConfig(t *testing.T) {
	logger := zap.NewNop()
	testIP := netip.MustParseAddr("192.168.1.100")

	tests := []struct {
		name           string
		appConfig      authAppConfig
		host           string
		inputIP        netip.Addr
		expectedConfig proxyConfig
	}{
		{
			name: "no_ssh_config_no_proxyjump",
			appConfig: authAppConfig{
				SshConfig: false,
			},
			host:    "testhost",
			inputIP: testIP,
			expectedConfig: proxyConfig{
				ip: testIP,
			},
		},
		{
			name: "app_config_proxyjump_takes_priority_over_ssh",
			appConfig: authAppConfig{
				ProxyJump: "app-proxy-host",
				SshConfig: true,
			},
			host:    "host1",
			inputIP: testIP,
			expectedConfig: proxyConfig{
				proxyJump: "app-proxy-host",
				ip:        testIP,
			},
		},
		{
			name: "app_config_proxyjump_without_ssh_config",
			appConfig: authAppConfig{
				ProxyJump: "direct-proxy",
				SshConfig: false,
			},
			host:    "anyhost",
			inputIP: testIP,
			expectedConfig: proxyConfig{
				proxyJump: "direct-proxy",
				ip:        testIP,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := authApp{
				config: tt.appConfig,
				log:    logger,
			}

			result := app.resolveProxyConfig(tt.host, tt.inputIP)

			// Check each field
			if result.proxyJump != tt.expectedConfig.proxyJump {
				t.Errorf("proxyJump: got %q, want %q", result.proxyJump, tt.expectedConfig.proxyJump)
			}
			if result.controlPath != tt.expectedConfig.controlPath {
				t.Errorf("controlPath: got %q, want %q", result.controlPath, tt.expectedConfig.controlPath)
			}
			if result.connectHost != tt.expectedConfig.connectHost {
				t.Errorf("connectHost: got %q, want %q", result.connectHost, tt.expectedConfig.connectHost)
			}
			if result.ip != tt.expectedConfig.ip {
				t.Errorf("ip: got %v, want %v", result.ip, tt.expectedConfig.ip)
			}
		})
	}
}

func TestResolveProxyConfigWithSSHConfig(t *testing.T) {
	// Test configurations as strings
	tests := []struct {
		name           string
		sshConfig      string
		host           string
		inputIP        netip.Addr
		expectedConfig proxyConfig
	}{
		{
			name: "hostname_only_no_proxyjump",
			sshConfig: `
Host test-host1
    Hostname real.server.example.com
    User admin
    Port 22
`,
			host:    "test-host1",
			inputIP: netip.MustParseAddr("10.0.0.1"),
			expectedConfig: proxyConfig{
				connectHost: "real.server.example.com",
				ip:          netip.Addr{}, // Should be cleared when Hostname is present
			},
		},
		{
			name: "test_case_hostname_with_ip",
			sshConfig: `
Host example.com
    HostName 194.113.200.100
`,
			host:    "example.com",
			inputIP: netip.MustParseAddr("10.0.0.10"),
			expectedConfig: proxyConfig{
				connectHost: "194.113.200.100",
				ip:          netip.Addr{}, // Should be cleared when Hostname is present
			},
		},
		{
			name: "proxyjump_and_hostname",
			sshConfig: `
Host test-host2
    Hostname internal.host.local
    ProxyJump jumphost.example.com
    ControlPath /tmp/test-ssh-%h-%p
    User deploy
`,
			host:    "test-host2",
			inputIP: netip.MustParseAddr("10.0.0.2"),
			expectedConfig: proxyConfig{
				proxyJump:   "jumphost.example.com",
				controlPath: "/tmp/test-ssh-%h-%p",
				connectHost: "internal.host.local",
				ip:          netip.Addr{}, // Should be cleared when Hostname is present
			},
		},
		{
			name: "proxyjump_only_no_hostname",
			sshConfig: `
Host test-host3
    ProxyJump bastion.example.com
    User operator
`,
			host:    "test-host3",
			inputIP: netip.MustParseAddr("10.0.0.3"),
			expectedConfig: proxyConfig{
				proxyJump: "bastion.example.com",
				ip:        netip.MustParseAddr("10.0.0.3"), // Should NOT be cleared (no Hostname)
			},
		},
		{
			name: "controlpath_only",
			sshConfig: `
Host test-host4
    ControlPath /var/run/ssh-control-%h-%p
    ControlMaster auto
`,
			host:    "test-host4",
			inputIP: netip.MustParseAddr("10.0.0.4"),
			expectedConfig: proxyConfig{
				controlPath: "/var/run/ssh-control-%h-%p",
				ip:          netip.MustParseAddr("10.0.0.4"),
			},
		},
		{
			name: "host_not_in_config",
			sshConfig: `
Host other-host
    Hostname other.example.com
`,
			host:    "unknown-host",
			inputIP: netip.MustParseAddr("10.0.0.5"),
			expectedConfig: proxyConfig{
				ip: netip.MustParseAddr("10.0.0.5"),
			},
		},
		{
			name: "wildcard_host_match",
			sshConfig: `
Host *.internal
    ProxyJump internal-gateway
    Hostname %h.company.local
`,
			host:    "server1.internal",
			inputIP: netip.MustParseAddr("10.0.0.6"),
			expectedConfig: proxyConfig{
				proxyJump:   "internal-gateway",
				connectHost: "server1.internal.company.local",
				ip:          netip.Addr{}, // Should be cleared
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary SSH config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config")

			if err := os.WriteFile(configPath, []byte(tt.sshConfig), 0600); err != nil {
				t.Fatalf("Failed to write test SSH config: %v", err)
			}

			// Override SSH config path for this test
			homeDir, err := os.UserHomeDir()
			if err != nil {
				t.Skip("Cannot get home directory")
			}

			originalConfigPath := filepath.Join(homeDir, ".ssh", "config")
			backupPath := originalConfigPath + ".test-backup"

			// Backup existing config if it exists
			if _, err := os.Stat(originalConfigPath); err == nil {
				if err := os.Rename(originalConfigPath, backupPath); err != nil {
					t.Logf("Warning: could not backup SSH config: %v", err)
				} else {
					defer func() {
						if err := os.Rename(backupPath, originalConfigPath); err != nil {
							t.Errorf("Failed to restore SSH config: %v", err)
						}
					}()
				}
			}

			// Copy test config to SSH config location
			sshDir := filepath.Join(homeDir, ".ssh")
			if err := os.MkdirAll(sshDir, 0700); err != nil {
				t.Skip("Cannot create .ssh directory")
			}

			testConfigContent, _ := os.ReadFile(configPath)
			if err := os.WriteFile(originalConfigPath, testConfigContent, 0600); err != nil {
				t.Skip("Cannot write SSH config")
			}
			defer os.Remove(originalConfigPath)

			// Run the test
			logger := zap.NewNop()
			app := authApp{
				config: authAppConfig{
					SshConfig: true,
				},
				log: logger,
			}

			result := app.resolveProxyConfig(tt.host, tt.inputIP)

			// Verify results
			if result.proxyJump != tt.expectedConfig.proxyJump {
				t.Errorf("proxyJump: got %q, want %q", result.proxyJump, tt.expectedConfig.proxyJump)
			}
			if result.controlPath != tt.expectedConfig.controlPath {
				t.Errorf("controlPath: got %q, want %q", result.controlPath, tt.expectedConfig.controlPath)
			}
			if result.connectHost != tt.expectedConfig.connectHost {
				t.Errorf("connectHost: got %q, want %q", result.connectHost, tt.expectedConfig.connectHost)
			}
			if result.ip != tt.expectedConfig.ip {
				t.Errorf("ip: got %v, want %v", result.ip, tt.expectedConfig.ip)
			}
		})
	}
}

func TestGetHostParams(t *testing.T) {
	// Create a temporary directory for test SSH config
	tmpDir, err := os.MkdirTemp("", "devuath_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a simple SSH config for testing
	sshConfigPath := filepath.Join(tmpDir, "config")
	sshConfigContent := `
Host testhost
    Hostname actual.server.com
    ProxyJump jumpserver
`
	if err := os.WriteFile(sshConfigPath, []byte(sshConfigContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Set SSH_CONFIG environment variable
	oldEnv := os.Getenv("SSH_CONFIG")
	os.Setenv("SSH_CONFIG", sshConfigPath)
	defer os.Setenv("SSH_CONFIG", oldEnv)

	logger := zap.NewNop()
	app := authApp{
		config: authAppConfig{
			SshConfig: true,
			Login:     "testuser",
		},
		log: logger,
	}

	// Test GetHostParams
	params := &pb.HostParams{
		Ip:     "10.0.0.1",
		Port:   22,
		Device: "cisco_ios",
	}

	result, err := app.GetHostParams("testhost", params)
	if err != nil {
		t.Fatalf("GetHostParams failed: %v", err)
	}

	// Check that the host field is set to the Hostname from SSH config
	if result.host != "actual.server.com" {
		t.Errorf("host: got %q, want %q", result.host, "actual.server.com")
	}

	// Check that IP is cleared when Hostname is present
	if result.ip.IsValid() {
		t.Errorf("IP should be cleared when Hostname is present, got: %v", result.ip)
	}

	// Check ProxyJump is set
	if result.proxyJump != "jumpserver" {
		t.Errorf("proxyJump: got %q, want %q", result.proxyJump, "jumpserver")
	}
}
