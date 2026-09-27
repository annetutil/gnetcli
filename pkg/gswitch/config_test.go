package gswitch_test

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/gswitch"
	"github.com/stretchr/testify/require"
)

func TestRunningConfigLoadAndSnapshot(t *testing.T) {
	var cfg gswitch.RunningConfig // The zero value must work too.
	require.Empty(t, cfg.String())
	require.NoError(t, cfg.Load("hostname lab\r\ninterface Ethernet2\r\n description old\r\n description second\r\n!\r\ninterface Ethernet1\r\n description first\r\n!\r\nend\r\n"))
	want := "hostname lab\ninterface Ethernet1\n description first\n!\ninterface Ethernet2\n description second\n!\n"
	require.Equal(t, want, cfg.String())
	copy := gswitch.NewRunningConfig()
	require.NoError(t, copy.Load(cfg.String()))
	require.Equal(t, want, copy.String())
	for _, text := range []string{"interface\n", " description orphan\n", "interface Ethernet1\n description\n", "interface range Ethernet1 Ethernet2\n"} {
		require.Error(t, cfg.Load(text))
		require.Equal(t, want, cfg.String(), "a failed load must not change state")
	}
}
