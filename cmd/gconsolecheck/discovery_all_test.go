package main

import (
	"bytes"
	"context"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/streamer/console"
	"github.com/stretchr/testify/require"
)

type fakeCommandInfo struct {
	port   int
	speed  int
	writer string
}

func (i fakeCommandInfo) GetPort() int     { return i.port }
func (i fakeCommandInfo) GetSpeed() int    { return i.speed }
func (i fakeCommandInfo) GetPCLwr() string { return i.writer }

func TestAllPortsDiscoveryPayloadContainsOnlyPrintableBytes(t *testing.T) {
	payload, err := makeAllPortsDiscoveryPayload("ttyS2", "run42")

	require.NoError(t, err)
	require.Len(t, payload, allPortsDiscoveryPayloadSize)
	for index, value := range payload {
		require.GreaterOrEqualf(t, value, byte(0x20), "byte %d is a control character", index)
		require.LessOrEqualf(t, value, byte(0x7e), "byte %d is not printable ASCII", index)
	}
	require.NotContains(t, payload, byte('\n'))
	require.NotContains(t, payload, byte('\r'))
	require.NotContains(t, payload, byte(0x05))
	require.NotContains(t, payload, byte(0xff))

	marker, err := parseAllPortsDiscoveryPayload(payload)
	require.NoError(t, err)
	require.Equal(t, allPortsMarker{source: "ttyS2", runID: "run42"}, marker)
}

func TestRunDiscoveryAllPortsFindsReciprocalPairs(t *testing.T) {
	a, b := newFakePair()
	c, d := newFakePair()
	sessions := map[string]dataSession{"ttyS1": a, "ttyS2": b, "ttyS3": c, "ttyS4": d}
	factory := func(_ context.Context, port string) (dataSession, error) {
		return sessions[port], nil
	}
	discover := func(context.Context) (console.CommandsInfoResult, error) {
		return console.CommandsInfoResult{
			"ttyS1": fakeCommandInfo{port: 10102, speed: 9600},
			"ttyS2": fakeCommandInfo{port: 10102, speed: 9600},
			"ttyS3": fakeCommandInfo{port: 10102, speed: 9600},
			"ttyS4": fakeCommandInfo{port: 10102, speed: 9600},
		}, nil
	}
	cfg := testConfig()
	cfg.parallel = 2
	cfg.timeout = time.Second
	var output bytes.Buffer

	err := runDiscoveryAllPorts(context.Background(), cfg, factory, discover, &output)

	require.NoError(t, err)
	require.Contains(t, output.String(), "DISCOVERED left=ttyS1 right=ttyS2")
	require.Contains(t, output.String(), "DISCOVERED left=ttyS3 right=ttyS4")
	require.Contains(t, output.String(), "DISCOVERY_SUMMARY ports=4 connected=4 pairs=2 unpaired=0 busy=0 errors=0")
}

func TestRunDiscoveryAllPortsReportsBusyPortWithoutConnecting(t *testing.T) {
	connected := false
	factory := func(_ context.Context, _ string) (dataSession, error) {
		connected = true
		return nil, io.ErrUnexpectedEOF
	}
	discover := func(context.Context) (console.CommandsInfoResult, error) {
		return console.CommandsInfoResult{"ttyS1": fakeCommandInfo{writer: "w@user@host@1"}}, nil
	}
	var output bytes.Buffer

	err := runDiscoveryAllPorts(context.Background(), testConfig(), factory, discover, &output)

	require.NoError(t, err)
	require.False(t, connected)
	require.Contains(t, output.String(), "DISCOVERY BUSY port=ttyS1")
}

func TestReportUnpairedDiscoveryPortShortensEmptyRead(t *testing.T) {
	state := &allPortsState{name: "ttyS4", readErr: context.DeadlineExceeded}
	var output bytes.Buffer

	reportUnpairedDiscoveryPort(&output, state)

	require.Equal(t, "DISCOVERY UNPAIRED port=ttyS4 reason=empty_read\n", output.String())
}

func TestReportDiscoveryReceivedOmitsSuccessfulReadDetails(t *testing.T) {
	state := &allPortsState{
		name:     "ttyS11",
		readData: make([]byte, allPortsDiscoveryPayloadSize),
		marker:   allPortsMarker{source: "ttyS27"},
	}
	var output bytes.Buffer

	reportDiscoveryReceived(&output, state)

	require.Equal(t, "DISCOVERY RECEIVED receiver=ttyS11 source=ttyS27\n", output.String())
}

func TestReportDiscoveryReceivedKeepsPartialReadDetails(t *testing.T) {
	state := &allPortsState{
		name:     "ttyS11",
		readData: []byte("partial"),
		readErr:  context.DeadlineExceeded,
		marker:   allPortsMarker{source: "ttyS27"},
	}
	var output bytes.Buffer

	reportDiscoveryReceived(&output, state)

	require.Contains(t, output.String(), "bytes=7")
	require.Contains(t, output.String(), "read_error=context deadline exceeded")
}

func TestConsolePortNaturalSort(t *testing.T) {
	ports := []string{"ttyS20", "ttyS3", "ttyS11", "ttyS2", "ttyS1"}

	sort.Slice(ports, func(left, right int) bool {
		return consolePortLess(ports[left], ports[right])
	})

	require.Equal(t, []string{"ttyS1", "ttyS2", "ttyS3", "ttyS11", "ttyS20"}, ports)
}

func TestConsolePortNaturalSortKeepsPrefixesSeparate(t *testing.T) {
	require.True(t, consolePortLess("ttyS2", "ttyS10"))
	require.True(t, consolePortLess("ttyS10", "ttyUSB2"))
	require.False(t, consolePortLess("ttyUSB2", "ttyS10"))
}
