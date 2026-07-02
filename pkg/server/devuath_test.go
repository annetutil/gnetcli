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

func TestResolveProxyConfigWithMockSSH(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name           string
		mockConfigs    map[string]map[string]string
		host           string
		inputIP        netip.Addr
		expectedConfig proxyConfig
	}{
		{
			name: "hostname_only_no_proxyjump",
			mockConfigs: map[string]map[string]string{
				"test-host1": {
					"Hostname": "real.server.example.com",
				},
			},
			host:    "test-host1",
			inputIP: netip.MustParseAddr("10.0.0.1"),
			expectedConfig: proxyConfig{
				connectHost: "real.server.example.com",
				ip:          netip.Addr{}, // Should be cleared when Hostname is present
			},
		},
		{
			name: "test_case_hostname_with_ip",
			mockConfigs: map[string]map[string]string{
				"example.com": {
					"Hostname": "194.113.200.100",
				},
			},
			host:    "example.com",
			inputIP: netip.MustParseAddr("10.0.0.10"),
			expectedConfig: proxyConfig{
				connectHost: "194.113.200.100",
				ip:          netip.Addr{}, // Should be cleared when Hostname is present
			},
		},
		{
			name: "proxyjump_and_hostname",
			mockConfigs: map[string]map[string]string{
				"test-host2": {
					"Hostname":    "internal.host.local",
					"ProxyJump":   "jumphost.example.com",
					"ControlPath": "/tmp/test-ssh-%h-%p",
				},
			},
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
			mockConfigs: map[string]map[string]string{
				"test-host3": {
					"ProxyJump": "bastion.example.com",
				},
			},
			host:    "test-host3",
			inputIP: netip.MustParseAddr("10.0.0.3"),
			expectedConfig: proxyConfig{
				proxyJump: "bastion.example.com",
				ip:        netip.MustParseAddr("10.0.0.3"), // Should NOT be cleared (no Hostname)
			},
		},
		{
			name: "controlpath_only",
			mockConfigs: map[string]map[string]string{
				"test-host4": {
					"ControlPath": "/var/run/ssh-control-%h-%p",
				},
			},
			host:    "test-host4",
			inputIP: netip.MustParseAddr("10.0.0.4"),
			expectedConfig: proxyConfig{
				controlPath: "/var/run/ssh-control-%h-%p",
				ip:          netip.MustParseAddr("10.0.0.4"),
			},
		},
		{
			name:        "host_not_in_config",
			mockConfigs: map[string]map[string]string{},
			host:        "unknown-host",
			inputIP:     netip.MustParseAddr("10.0.0.5"),
			expectedConfig: proxyConfig{
				ip: netip.MustParseAddr("10.0.0.5"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSSH := mockSSHConfigReader{configs: tt.mockConfigs}
			app := authApp{
				config: authAppConfig{
					SshConfig: true,
				},
				log:       logger,
				sshConfig: mockSSH,
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
