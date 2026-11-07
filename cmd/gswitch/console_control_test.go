package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSSHConsoleAndControlProcess(t *testing.T) {
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready.json")
	root, err := filepath.Abs("../../examples/gswitch")
	require.NoError(t, err)
	const token = "local-test-control-token"
	args, err := json.Marshal([]string{"-host", "127.0.0.1", "-port", "0", "-profile", filepath.Join(root, "aruba.yaml"), "-scenario", filepath.Join(root, "aruba-dhcp.yaml"), "-ssh-mode", "console", "-username", "ssh-user", "-password", "ssh-secret", "-console-username", "device-user", "-console-password", "device-secret", "-console-port", "0", "-control-port", "0", "-control-token", token, "-ready-file", ready})
	require.NoError(t, err)
	processContext, stopProcess := context.WithTimeout(t.Context(), 20*time.Second)
	defer stopProcess()
	process := exec.CommandContext(processContext, os.Args[0], "-test.run=^TestEmulatorChildProcess$")
	process.Env = append(os.Environ(), "GSWITCH_EMULATOR_CHILD=1", "GSWITCH_EMULATOR_ARGS="+string(args))
	logfile, err := os.Create(filepath.Join(dir, "server.log"))
	require.NoError(t, err)
	defer logfile.Close()
	process.Stdout = logfile
	process.Stderr = logfile
	require.NoError(t, process.Start())
	t.Cleanup(func() { _ = process.Process.Kill() })
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	var addresses map[string]string
	require.Eventually(t, func() bool { b, e := os.ReadFile(ready); return e == nil && json.Unmarshal(b, &addresses) == nil }, 5*time.Second, 10*time.Millisecond)
	httpClient := &http.Client{Timeout: time.Second}
	request := func(method, path, body string) []byte {
		req, e := http.NewRequest(method, "http://"+addresses["control"]+path, bytes.NewBufferString(body))
		require.NoError(t, e)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, e := httpClient.Do(req)
		require.NoError(t, e)
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		require.NoError(t, e)
		require.Equal(t, 200, res.StatusCode, string(b))
		return b
	}
	client, err := ssh.Dial("tcp", addresses["ssh"], &ssh.ClientConfig{User: "ssh-user", Auth: []ssh.AuthMethod{ssh.Password("ssh-secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.NoError(t, err)
	defer client.Close()
	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()
	in, err := session.StdinPipe()
	require.NoError(t, err)
	out, err := session.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, session.RequestPty("vt100", 24, 80, nil))
	require.NoError(t, session.Shell())
	reader := bufio.NewReader(out)
	read := func(suffix string) string {
		var b strings.Builder
		for !strings.HasSuffix(b.String(), suffix) {
			c, e := reader.ReadByte()
			require.NoError(t, e)
			b.WriteByte(c)
		}
		return b.String()
	}
	var state emulator.Snapshot
	require.Eventually(t, func() bool {
		require.NoError(t, json.Unmarshal(request("GET", "/v1/state", ""), &state))
		return len(state.Sessions) == 1 && state.Sessions[0].Attached
	}, time.Second, 10*time.Millisecond)
	require.False(t, state.LoginReady)
	raw, e := net.DialTimeout("tcp", addresses["console"], time.Second)
	require.NoError(t, e)
	require.NoError(t, raw.SetReadDeadline(time.Now().Add(time.Second)))
	var one [1]byte
	_, e = raw.Read(one[:])
	require.ErrorIs(t, e, io.EOF)
	raw.Close()

	request("POST", "/v1/events", `{"kind":"raw","route":"console","text":"DHCP-probe\r\n"}`)
	require.Contains(t, read("DHCP-probe\r\n"), "DHCP-probe")
	request("POST", "/v1/events", `{"kind":"ready","text":"true"}`)
	read("User: ")
	_, err = io.WriteString(in, "device-user\n")
	require.NoError(t, err)
	read("Password: ")
	_, err = io.WriteString(in, "device-secret\n")
	require.NoError(t, err)
	read("02:00:00:00:00:01# ")

	// Detach the transport while retaining device login and an editing draft.
	_, err = io.WriteString(in, "show ver")
	require.NoError(t, err)
	read("show ver")
	require.NoError(t, session.Close())
	require.NoError(t, client.Close())
	require.Eventually(t, func() bool {
		require.NoError(t, json.Unmarshal(request("GET", "/v1/state", ""), &state))
		return !state.Sessions[0].Attached
	}, time.Second, 10*time.Millisecond)
	client, err = ssh.Dial("tcp", addresses["ssh"], &ssh.ClientConfig{User: "ssh-user", Auth: []ssh.AuthMethod{ssh.Password("ssh-secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: time.Second})
	require.NoError(t, err)
	defer client.Close()
	session, err = client.NewSession()
	require.NoError(t, err)
	defer session.Close()
	in, err = session.StdinPipe()
	require.NoError(t, err)
	out, err = session.StdoutPipe()
	require.NoError(t, err)
	reader = bufio.NewReader(out)
	require.NoError(t, session.RequestPty("vt100", 24, 80, nil))
	require.NoError(t, session.Shell())
	require.Equal(t, "02:00:00:00:00:01# show ver", read("# show ver"))
	_, err = io.WriteString(in, "sion\n")
	require.NoError(t, err)
	require.Contains(t, read("02:00:00:00:00:01# "), "ArubaOS")
	require.NoError(t, session.WindowChange(10, 40))
	require.Eventually(t, func() bool {
		require.NoError(t, json.Unmarshal(request("GET", "/v1/state", ""), &state))
		return state.Sessions[0].Columns == 40 && state.Sessions[0].Rows == 10
	}, time.Second, 10*time.Millisecond)
	request("POST", "/v1/reboot", `{}`)
	request("POST", "/v1/events", `{"kind":"raw","route":"console","text":"after-reboot\r\n"}`)
	require.Contains(t, read("after-reboot\r\n"), "after-reboot")
	request("POST", "/v1/events", `{"kind":"ready","text":"true"}`)
	read("User: ")
	require.NoError(t, process.Process.Signal(syscall.SIGTERM))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("process did not stop")
	}
	_, err = os.Stat(ready)
	require.True(t, os.IsNotExist(err))
}
