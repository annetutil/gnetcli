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

func TestHuaweiSSHInterfaceValuesAndFamilies(t *testing.T) {
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
	send("display interface ?")
	display := read("<sw1>display interface ")
	require.Contains(t, display, "  100GE            100GE interface\r\n")
	require.Contains(t, display, "  LoopBack         LoopBack interface\r\n")
	require.Contains(t, display, "  brief            Summary information about the interface status and\r\n                   configuration\r\n")
	require.Contains(t, display, "  <cr>\r\n\r\n<sw1>display interface ")
	require.NotContains(t, display, "Current view commands:")
	require.Equal(t, before, d.Snapshot())
	send("\x03")
	read("<sw1>")
	send("system-view\n")
	read("[~sw1]")
	send("interface ?")
	interfaces := read("[~sw1]interface ")
	require.Contains(t, interfaces, "  GE0/0/1   Interface name\r\n")
	require.Contains(t, interfaces, "  100GE     100GE interface\r\n")
	require.Contains(t, interfaces, "  LoopBack  LoopBack interface\r\n")
	require.NotContains(t, interfaces, "<name:word>")
	before = d.Snapshot()
	send("GE\t")
	require.Equal(t, "GE0/0/1 ", read("GE0/0/1 "))
	require.Equal(t, before, d.Snapshot())
	send("\n")
	read("[~sw1-GE0/0/1]")
	send("quit\n")
	read("[~sw1]")
	send("interface loop\t")
	read("LoopBack ")
	send("123\n")
	read("[~sw1-LoopBack123]")
	send("description loopback-test\n")
	read("[*sw1-LoopBack123]")
	send("quit\n")
	read("[*sw1]")
	send("interface LoopBack ?")
	require.Contains(t, read("[*sw1]interface LoopBack "), "  123  Interface number\r\n")
	send("\t")
	require.Equal(t, "123 ", read("123 "))
	send("\n")
	read("[*sw1-LoopBack123]")
}
