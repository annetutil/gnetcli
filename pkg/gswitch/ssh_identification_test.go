package gswitch_test

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/gswitch"
	"github.com/stretchr/testify/require"
)

func TestSSHIdentification(t *testing.T) {
	address, _ := startSwitch(t, gswitch.SSHServerOptions{Username: "test", Password: "secret"}, false)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	identification, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	// RFC 4253 section 4.2: protocol version is mandatory. Go's SSH client
	// accepted our old SSH-gswitch string, but OpenSSH correctly rejected it.
	require.Equal(t, "SSH-2.0-gswitch\r\n", identification)
}

func TestOpenSSHVersionExchange(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH executable not installed")
	}
	address, _ := startSwitch(t, gswitch.SSHServerOptions{Username: "test", Password: "secret"}, false)
	host, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// This intentionally stops at authentication: no credentials or user SSH
	// settings/agents/known-host files are read. Host checking is disabled only
	// for this isolated ephemeral loopback fixture.
	command := exec.CommandContext(ctx, ssh, "-F", "/dev/null", "-vv", "-T",
		"-o", "BatchMode=yes",
		"-o", "PreferredAuthentications=none",
		"-o", "IdentityAgent=none",
		"-o", "IdentityFile=none",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=2",
		"-o", "ConnectionAttempts=1",
		"-p", port, "test@"+host)
	output, err := command.CombinedOutput()
	require.Error(t, err, "authentication is deliberately disabled")
	require.NoError(t, ctx.Err(), "%s", output)
	require.Contains(t, string(output), "Remote protocol version 2.0, remote software version gswitch")
	require.Contains(t, string(output), "Authentications that can continue:")
	require.Contains(t, string(output), "Permission denied")
	require.NotContains(t, string(output), "Bad remote protocol version")
}
