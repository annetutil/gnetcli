package gswitch_test

import (
	"context"
	"github.com/annetutil/gnetcli/pkg/gswitch"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"io"
	"testing"
	"time"
)

func TestSSHSessionPTYAndResize(t *testing.T) {
	infos := make(chan gswitch.SSHSession, 1)
	address, _ := startSwitch(t, gswitch.SSHServerOptions{Username: "test", Password: "secret", SSHSessionHandler: func(ctx context.Context, stream io.ReadWriteCloser, info gswitch.SSHSession) error {
		infos <- info
		<-ctx.Done()
		return ctx.Err()
	}}, false)
	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.NoError(t, err)
	defer client.Close()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()
	require.Error(t, session.RequestPty("vt100", 24, 5000, nil))
	require.NoError(t, session.RequestPty("vt100", 24, 80, nil))
	require.NoError(t, session.Shell())
	var info gswitch.SSHSession
	select {
	case info = <-infos:
	case <-time.After(time.Second):
		t.Fatal("no SSH metadata")
	}
	require.Equal(t, "test", info.Username)
	require.Equal(t, gswitch.TerminalSize{Columns: 80, Rows: 24}, info.Size)
	require.NoError(t, session.WindowChange(10, 32))
	select {
	case size := <-info.Resizes:
		require.Equal(t, gswitch.TerminalSize{Columns: 32, Rows: 10}, size)
	case <-time.After(time.Second):
		t.Fatal("no resize")
	}
	require.NoError(t, session.WindowChange(0, 60))
	select {
	case size := <-info.Resizes:
		require.Equal(t, gswitch.TerminalSize{Columns: 60, Rows: 10}, size)
	case <-time.After(time.Second):
		t.Fatal("no partial resize")
	}
	_, err = client.Dial("tcp", "127.0.0.1:9")
	require.Error(t, err)
	exec, err := client.NewSession()
	require.NoError(t, err)
	defer exec.Close()
	require.Error(t, exec.Run("show version"))
}
