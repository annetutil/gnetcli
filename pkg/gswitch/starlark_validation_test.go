package gswitch_test

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/huawei"
	sshstream "github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"github.com/stretchr/testify/require"
)

func TestStarlarkRejectionRecognizedByCiscoClient(t *testing.T) {
	d := newEmulatedSwitch(t, "iosxe.yaml")
	address, _ := startSwitch(t, emulatedOptions(d), false)
	dev := openDevice(t, address, passwordCredentials(), false)
	execute(t, dev, "configure terminal", "interface Ethernet2")
	before := d.Snapshot()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := dev.ExecuteCtx(ctx, cmd.NewCmd("description initial"))
	require.NoError(t, err)
	require.NotZero(t, result.Status())
	require.Contains(t, string(result.Error()), "Ethernet1 and Ethernet2")
	require.Equal(t, before.Running, d.Snapshot().Running)
	execute(t, dev, "description access", "end")
	require.Contains(t, execute(t, dev, "show running-config"), "description access")
}

func TestStarlarkCommitRejectionRecognizedByHuaweiClient(t *testing.T) {
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
	before := d.Snapshot()
	execute(t, &dev, "system-view", "interface GE0/0/2", "description initial")
	result, err := dev.ExecuteCtx(ctx, cmd.NewCmd("commit"))
	require.NoError(t, err)
	require.NotZero(t, result.Status())
	require.Contains(t, string(result.Error()), "GE0/0/1 and GE0/0/2")
	require.Equal(t, before.Running, d.Snapshot().Running)
	execute(t, &dev, "description access", "commit", "return")
	require.Contains(t, execute(t, &dev, "display current-configuration"), "description access")
}
