package gswitch_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/device/huawei"
	sshstream "github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestHuaweiSSHAaaViewAndDisplayThis(t *testing.T) {
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
	send("aaa\n")
	read("[~sw1-aaa]")
	send("dis\t")
	require.Equal(t, "display ", read("display "))
	send("this\n")
	want := "#\r\naaa\r\n undo local-user policy security-enhance\r\n default-domain admin localuser\r\n service-type terminal force-domain default0\r\n#\r\nreturn\r\n"
	require.Equal(t, "this\r\n"+want+"[~sw1-aaa]", read("[~sw1-aaa]"))
	send("default-domain admin operators\n")
	read("[*sw1-aaa]")
	send("display  this\n")
	require.Equal(t, "display  this\r\n"+want+"[*sw1-aaa]", read("[*sw1-aaa]"))
	send("commit\n")
	read("[~sw1-aaa]")
	send("dis this\n")
	require.Equal(t, "dis this\r\n"+strings.Replace(want, "admin localuser", "admin operators", 1)+"[~sw1-aaa]", read("[~sw1-aaa]"))
	send("q\n")
	read("[~sw1]")
	send("dis this\n")
	rootConfig := "#\r\nsysname sw1\r\n" + strings.TrimSuffix(strings.Replace(want, "admin localuser", "admin operators", 1), "return\r\n") + "interface GE0/0/1\r\n description initial\r\n#\r\nreturn\r\n"
	require.Equal(t, "dis this\r\n"+rootConfig+"[~sw1]", read("[~sw1]"))
	send("return\n")
	read("<sw1>")
}

func TestHuaweiClientDisplayThisInAAAView(t *testing.T) {
	d := newEmulatedSwitch(t, "huawei.yaml")
	address, _ := startSwitch(t, emulatedOptions(d), false)
	host, port, err := net.SplitHostPort(address)
	require.NoError(t, err)
	n, err := strconv.Atoi(port)
	require.NoError(t, err)
	dev := huawei.NewDevice(sshstream.NewStreamer(host, passwordCredentials(), sshstream.WithPort(n)))
	defer dev.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, dev.Connect(ctx))
	execute(t, &dev, "system-view", "aaa")
	out := execute(t, &dev, "dis this")
	require.Contains(t, out, "default-domain admin localuser")
	require.NotContains(t, out, "sysname")
	execute(t, &dev, "default-domain admin operators")
	require.Contains(t, execute(t, &dev, "dis this"), "default-domain admin localuser")
	execute(t, &dev, "commit")
	require.Contains(t, execute(t, &dev, "dis this"), "default-domain admin operators")
	execute(t, &dev, "quit")
	out = execute(t, &dev, "dis this")
	require.Contains(t, out, "sysname sw1")
	require.Contains(t, out, "default-domain admin operators")
	require.Contains(t, out, "interface GE0/0/1")
	require.Contains(t, out, "description initial")
	execute(t, &dev, "return")
}
