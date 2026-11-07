package gswitch_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestHuaweiSSHSysname(t *testing.T) {
	d := newEmulatedSwitch(t, "huawei.yaml")
	address, _ := startSwitch(t, emulatedOptions(d), false)
	conn, err := net.DialTimeout("tcp", address, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	config := &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	c, chans, requests, err := ssh.NewClientConn(conn, address, config)
	require.NoError(t, err)
	client := ssh.NewClient(c, chans, requests)
	defer client.Close()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()
	stdin, err := session.StdinPipe()
	require.NoError(t, err)
	stdout, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.RequestPty("vt100", 24, 80, nil))
	require.NoError(t, session.Shell())
	reader := bufio.NewReader(stdout)
	read := func(suffix string) string {
		var out strings.Builder
		for !strings.HasSuffix(out.String(), suffix) {
			b, err := reader.ReadByte()
			require.NoError(t, err)
			out.WriteByte(b)
		}
		return out.String()
	}
	send := func(text string) { _, err := io.WriteString(stdin, text); require.NoError(t, err) }
	read("<sw1>")
	send("system-view\n")
	read("[~sw1]")
	send("sysname ?")
	require.Equal(t, "sysname ?\r\n  TEXT<1-246>  Host name (1 to 246 characters)\r\n\r\n[~sw1]sysname ", read("[~sw1]sysname "))
	send("Lab-SW2\n")
	require.Equal(t, "Lab-SW2\r\n[*Lab-SW2]", read("[*Lab-SW2]"))
	require.Equal(t, "sw1", d.Snapshot().Running["hostname"])
	send("commit\n")
	read("[~Lab-SW2]")
	send("return\n")
	read("<Lab-SW2>")
	send("display current-configuration\n")
	require.Contains(t, read("<Lab-SW2>"), "sysname Lab-SW2\r\n")
	send("system-view\n")
	read("[~Lab-SW2]")
	send("sysname " + strings.Repeat("x", 247) + "\n")
	require.Contains(t, read("[~Lab-SW2]"), "Error: Unrecognized command found at '^' position.")
	require.Equal(t, "Lab-SW2", d.Snapshot().Running["hostname"])
}
