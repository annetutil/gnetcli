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

func TestHuaweiSSHSingleLevelHelp(t *testing.T) {
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
	before := d.Snapshot()
	send("display\n")
	require.Equal(t, "display\r\n             ^\r\nError: Incomplete command found at '^' position.\r\n<sw1>", read("<sw1>"))
	send("display nonexistent\n")
	require.Equal(t, "display nonexistent\r\n             ^\r\nError: Unrecognized command found at '^' position.\r\n<sw1>", read("<sw1>"))
	send("?")
	root := read("<sw1>")
	require.Contains(t, root, "?\r\nCurrent view commands:\r\n")
	require.Equal(t, 1, strings.Count(root, "  display "))
	require.Contains(t, root, "  display           Display current system information")
	require.NotContains(t, root, "current-configuration")
	require.NotContains(t, root, "version")
	send("display ?")
	children := read("<sw1>display ")
	require.Contains(t, children, "  current-configuration  Display current configuration")
	require.Contains(t, children, "  version                Display system version")
	require.NotContains(t, children, "Current view commands:")
	require.NotContains(t, children, "  display ")
	require.Equal(t, before, d.Snapshot())
	send("version\n")
	require.Contains(t, read("<sw1>"), "Huawei VRP")
	send("display info-center ?")
	infoCenter := read("<sw1>display info-center ")
	require.Equal(t, "display info-center ?\r\n"+
		"  channel     Set the name of information channel\r\n"+
		"  statistics  Information statistics data of all modules\r\n"+
		"  |           Matching output\r\n"+
		"  >           Redirect the output to a file\r\n"+
		"  >>          Redirect the output to a file in append mode\r\n"+
		"  <cr>\r\n\r\n<sw1>display info-center ", infoCenter)
	require.Equal(t, before, d.Snapshot())
	send("\n")
	require.Contains(t, read("<sw1>"), "not implemented in this emulator profile")
	send("system-view\n")
	read("[~sw1]")
	send("?")
	system := read("[~sw1]")
	require.Contains(t, system, "  interface         Enter interface view")
	require.NotContains(t, system, "display")
	send("interface ?")
	require.Contains(t, read("[~sw1]interface "), "Interface name")
	require.Equal(t, "system", d.Snapshot().Sessions[0].Mode)
}
