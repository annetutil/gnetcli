package main

import (
	"bytes"
	"flag"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	cfg, err := parseConfig([]string{
		"-host", "conserver.example.net",
		"-port", "10102",
		"-username", "tester",
		"-speed", "115200",
		"-timeout", "3s",
		"-read-timeout", "7s",
		"-duration", "2m",
		"-extra-wait", "1500ms",
		"-chunk-size", "8192",
		"-parallel", "2",
		"-seed", "0x2a",
		"-t", "ttyS1=ttyS2",
		"-t", "ttyS3=ttyS4",
		"-scenario", "test_all_bytes",
		"-scenario", "test_all_bytes",
		"-debug",
		"-ssl",
		"-J", "jump-user@jump.example.net",
		"-use-ssh-config",
		"-ssh-config-passphrase", "test-passphrase",
	}, io.Discard)

	require.NoError(t, err)
	require.Equal(t, "conserver.example.net", cfg.host)
	require.Equal(t, 10102, cfg.port)
	require.Equal(t, "tester", cfg.username)
	require.Equal(t, 115200, cfg.speed)
	require.Equal(t, 7*time.Second, cfg.readTimeout)
	require.Equal(t, 1500*time.Millisecond, cfg.extraWait)
	require.Equal(t, uint64(42), cfg.seed)
	require.Equal(t, 2, cfg.parallel)
	require.True(t, cfg.debug)
	require.True(t, cfg.ssl)
	require.Equal(t, "jump-user@jump.example.net", cfg.jumpHost)
	require.True(t, cfg.useSSHConfig)
	require.Equal(t, "test-passphrase", cfg.sshPassphrase)
	require.Equal(t, []portPair{{left: "ttyS1", right: "ttyS2"}, {left: "ttyS3", right: "ttyS4"}}, cfg.pairs)
	require.Equal(t, []string{"test_all_bytes"}, cfg.scenarios)
}

func TestParseConfigDefaultsToAllScenarios(t *testing.T) {
	cfg, err := parseConfig([]string{"-host", "localhost", "-t", "left=right"}, io.Discard)

	require.NoError(t, err)
	require.Equal(t, defaultScenarioNames, cfg.scenarios)
	require.NotContains(t, cfg.scenarios, "test_random_soak_ascii")
	require.NotContains(t, cfg.scenarios, "test_discovery")
	require.True(t, cfg.ssl)
	require.Equal(t, cfg.timeout, cfg.readTimeout)
}

func TestParseConfigCanDisableSSL(t *testing.T) {
	cfg, err := parseConfig([]string{"-host", "localhost", "-t", "left=right", "-ssl=false"}, io.Discard)

	require.NoError(t, err)
	require.False(t, cfg.ssl)
}

func TestParseConfigEnablesASCIISoakExplicitly(t *testing.T) {
	cfg, err := parseConfig([]string{"-host", "localhost", "-t", "left=right", "-scenario", "test_random_soak_ascii"}, io.Discard)

	require.NoError(t, err)
	require.Equal(t, []string{"test_random_soak_ascii"}, cfg.scenarios)
}

func TestParseConfigEnablesDiscoveryExplicitly(t *testing.T) {
	cfg, err := parseConfig([]string{"-host", "localhost", "-t", "left=right", "-scenario", "test_discovery"}, io.Discard)

	require.NoError(t, err)
	require.Equal(t, []string{"test_discovery"}, cfg.scenarios)
}

func TestParseConfigAllowsAllPortsDiscoveryWithoutPairs(t *testing.T) {
	cfg, err := parseConfig([]string{"-host", "localhost", "-scenario", "test_discovery_all_ports"}, io.Discard)

	require.NoError(t, err)
	require.Empty(t, cfg.pairs)
	require.Equal(t, []string{"test_discovery_all_ports"}, cfg.scenarios)
}

func TestParseConfigStillRequiresPairsForMixedScenarios(t *testing.T) {
	_, err := parseConfig([]string{"-host", "localhost", "-scenario", "test_discovery_all_ports", "-scenario", "test_all_bytes"}, io.Discard)

	require.ErrorContains(t, err, "at least one -t")
}

func TestParseConfigRejectsInvalidInput(t *testing.T) {
	testCases := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing host", args: []string{"-t", "a=b"}, want: "-host is required"},
		{name: "missing pair", args: []string{"-host", "localhost"}, want: "at least one -t"},
		{name: "bad pair", args: []string{"-host", "localhost", "-t", "a"}, want: "expected left=right"},
		{name: "empty side", args: []string{"-host", "localhost", "-t", "a="}, want: "both port names"},
		{name: "same side", args: []string{"-host", "localhost", "-t", "a=a"}, want: "ports must differ"},
		{name: "reused port", args: []string{"-host", "localhost", "-t", "a=b", "-t", "b=c"}, want: "is used by both"},
		{name: "unknown scenario", args: []string{"-host", "localhost", "-t", "a=b", "-scenario", "unknown"}, want: "unknown scenario"},
		{name: "bad speed", args: []string{"-host", "localhost", "-t", "a=b", "-speed", "1200"}, want: "unsupported -speed"},
		{name: "bad read timeout", args: []string{"-host", "localhost", "-t", "a=b", "-read-timeout", "-1s"}, want: "-read-timeout must be positive"},
		{name: "bad parallel", args: []string{"-host", "localhost", "-t", "a=b", "-parallel", "-1"}, want: "-parallel must be non-negative"},
		{name: "bad extra wait", args: []string{"-host", "localhost", "-t", "a=b", "-extra-wait", "0"}, want: "-extra-wait must be positive"},
		{name: "ssh config without jump", args: []string{"-host", "localhost", "-t", "a=b", "-use-ssh-config"}, want: "-use-ssh-config requires -J"},
		{name: "passphrase without ssh config", args: []string{"-host", "localhost", "-t", "a=b", "-J", "jump", "-ssh-config-passphrase", "pass"}, want: "-ssh-config-passphrase requires -use-ssh-config"},
		{name: "empty jump user", args: []string{"-host", "localhost", "-t", "a=b", "-J", "@jump"}, want: "invalid jump host"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := parseConfig(testCase.args, io.Discard)
			require.ErrorContains(t, err, testCase.want)
		})
	}
}

func TestHelpDescribesAllScenarios(t *testing.T) {
	var output bytes.Buffer

	_, err := parseConfig([]string{"-h"}, &output)

	require.ErrorIs(t, err, flag.ErrHelp)
	for _, name := range allScenarioNames {
		require.Contains(t, output.String(), name)
		require.Contains(t, output.String(), scenarioDescriptions[name])
	}
}

func TestSeedIsUsed(t *testing.T) {
	require.True(t, seedIsUsed([]string{"test_one_way"}))
	require.True(t, seedIsUsed([]string{"test_random_soak"}))
	require.True(t, seedIsUsed([]string{"test_random_soak_ascii"}))
	require.True(t, seedIsUsed([]string{"test_discovery"}))
	require.True(t, seedIsUsed([]string{"test_discovery_all_ports"}))
	require.True(t, seedIsUsed([]string{"test_all_bytes", "test_random_soak"}))
	require.False(t, seedIsUsed([]string{"test_all_bytes"}))
}
