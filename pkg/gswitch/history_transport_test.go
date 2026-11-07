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

func TestSSHSessionHistoryArrows(t *testing.T) {
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
	openShell := func() (func(string), func(string) string) {
		session, err := client.NewSession()
		require.NoError(t, err)
		t.Cleanup(func() { session.Close() })
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
		return send, read
	}
	send, read := openShell()
	send("display version\n")
	require.Contains(t, read("<sw1>"), "Huawei VRP")
	send("display current-configuration\n")
	require.Contains(t, read("<sw1>"), "sysname sw1")
	// Even two shell channels in the same SSH connection have separate histories.
	sendOther, readOther := openShell()
	sendOther("\x1b[A")
	require.Equal(t, "\a", readOther("\a"))
	before := d.Snapshot()
	send("disp\x1b[A")
	require.Equal(t, "disp\r\x1b[2K<sw1>display current-configuration", read("display current-configuration"))
	send("\x1bOA")
	require.Equal(t, "\r\x1b[2K<sw1>display version", read("display version"))
	send("\x1bOB")
	require.Equal(t, "\r\x1b[2K<sw1>display current-configuration", read("display current-configuration"))
	send("\x1b[B")
	require.Equal(t, "\r\x1b[2K<sw1>disp", read("<sw1>disp"))
	require.Equal(t, before, d.Snapshot())
	send("\x03")
	read("<sw1>")
	send("\x1b[A")
	read("display current-configuration")
	send("\n")
	require.Contains(t, read("<sw1>"), "sysname sw1")
	sendOther("display version\n")
	readOther("<sw1>")
	sendOther("\x1b[A")
	require.Equal(t, "\r\x1b[2K<sw1>display version", readOther("display version"))
	send("\x1b[A")
	require.Equal(t, "\r\x1b[2K<sw1>display current-configuration", read("display current-configuration"))
}
