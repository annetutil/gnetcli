package main

import (
	"bytes"
	"context"
	"io"
	"sort"
	"strings"
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

func TestAllPortsDiscoveryPayloadContainsNewlineAndProbe(t *testing.T) {
	payload, err := makeAllPortsDiscoveryPayload("ttyS2", "run42")

	require.NoError(t, err)
	require.Len(t, payload, allPortsDiscoveryPayloadSize)
	line, probe, ok := strings.Cut(string(payload), "\n")
	require.True(t, ok)
	require.Equal(t, "|test=test_discovery_all_ports|source=ttyS2|run=run42|", line)
	require.Regexp(t, `^[0-9a-f]{16}$`, strings.TrimRight(probe, " "))
	require.Equal(t, 1, bytes.Count(payload, []byte{'\n'}))
	for index, value := range payload {
		if value == '\n' {
			continue
		}
		require.GreaterOrEqualf(t, value, byte(0x20), "byte %d is a control character", index)
		require.LessOrEqualf(t, value, byte(0x7e), "byte %d is not printable ASCII", index)
	}
	require.NotContains(t, payload, byte('\r'))
	require.NotContains(t, payload, byte(0x05))
	require.NotContains(t, payload, byte(0xff))

	marker, err := parseAllPortsDiscoveryPayload(payload)
	require.NoError(t, err)
	require.Equal(t, allPortsMarker{source: "ttyS2", runID: "run42"}, marker)
}

func TestRunDiscoveryAllPortsRejectsLoginEcho(t *testing.T) {
	testCases := []struct {
		name      string
		transform func([]byte) []byte
	}{
		{
			name: "marker only",
			transform: func(data []byte) []byte {
				return data[:bytes.IndexByte(data, '\n')]
			},
		},
		{
			name: "password prompt instead of probe",
			transform: func(data []byte) []byte {
				return append(data[:bytes.IndexByte(data, '\n')+1], []byte("Password: ")...)
			},
		},
		{
			name: "terminal changes newline",
			transform: func(data []byte) []byte {
				return bytes.ReplaceAll(data, []byte{'\n'}, []byte{'\r', '\n'})
			},
		},
		{
			name: "truncated probe",
			transform: func(data []byte) []byte {
				return data[:bytes.IndexByte(data, '\n')+5]
			},
		},
		{
			name: "corrupt probe",
			transform: func(data []byte) []byte {
				data[bytes.IndexByte(data, '\n')+1] ^= 1
				return data
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			session, _ := newFakePair()
			session.peer = session
			session.transform = testCase.transform
			factory := func(context.Context, string) (dataSession, error) { return session, nil }
			discover := func(context.Context) (console.CommandsInfoResult, error) {
				return console.CommandsInfoResult{"ttyS5": fakeCommandInfo{}}, nil
			}
			cfg := testConfig()
			cfg.timeout = 100 * time.Millisecond
			var output bytes.Buffer

			err := runDiscoveryAllPorts(context.Background(), cfg, factory, discover, &output)

			require.NoError(t, err)
			require.Contains(t, output.String(), "DISCOVERY UNPAIRED port=ttyS5")
			require.NotContains(t, output.String(), "DISCOVERY SELF_LOOP")
			require.NotContains(t, output.String(), "DISCOVERY RECEIVED")
			require.NotContains(t, output.String(), "DISCOVERED ")
			require.Contains(t, output.String(), "ports=1 connected=1 pairs=0 unpaired=1 busy=0 errors=0")
		})
	}
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

func TestRunDiscoveryAllPortsReportsSelfLoopOnce(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "complete read"
		if partial {
			name = "partial read"
		}
		t.Run(name, func(t *testing.T) {
			session, _ := newFakePair()
			session.peer = session
			if partial {
				session.transform = func(data []byte) []byte {
					return data[:len(data)-1]
				}
			}
			factory := func(context.Context, string) (dataSession, error) {
				return session, nil
			}
			discover := func(context.Context) (console.CommandsInfoResult, error) {
				return console.CommandsInfoResult{"ttyS5": fakeCommandInfo{}}, nil
			}
			cfg := testConfig()
			var output bytes.Buffer

			err := runDiscoveryAllPorts(context.Background(), cfg, factory, discover, &output)

			require.NoError(t, err)
			require.Equal(t, 1, strings.Count(output.String(), "DISCOVERY SELF_LOOP port=ttyS5"))
			require.NotContains(t, output.String(), "DISCOVERY RECEIVED")
			require.Contains(t, output.String(), "DISCOVERY_SUMMARY ports=1 connected=1 pairs=0 unpaired=1 busy=0 errors=0")
			if partial {
				require.Contains(t, output.String(), "DISCOVERY SELF_LOOP port=ttyS5 bytes=127 read_error=")
			} else {
				require.Contains(t, output.String(), "DISCOVERY SELF_LOOP port=ttyS5\n")
			}
		})
	}
}

func TestReportUnpairedDiscoveryPortShortensEmptyRead(t *testing.T) {
	state := &allPortsState{name: "ttyS4", readErr: context.DeadlineExceeded}
	var output bytes.Buffer

	reportUnpairedDiscoveryPort(&output, state)

	require.Equal(t, "DISCOVERY UNPAIRED port=ttyS4 reason=empty_read\n", output.String())
}

func TestReportUnpairedDiscoveryPortShowsReceivedData(t *testing.T) {
	state := &allPortsState{
		name:      "ttyS7",
		readData:  []byte("login:\r\n\x1b\xff"),
		readErr:   context.DeadlineExceeded,
		markerErr: io.ErrUnexpectedEOF,
	}
	var output bytes.Buffer

	reportUnpairedDiscoveryPort(&output, state)

	require.Equal(t, "DISCOVERY UNPAIRED port=ttyS7 received=true bytes=10 data=\"login:\\r\\n\\x1b\\xff\" marker_not_received=true read_error=context deadline exceeded marker_error=unexpected EOF\n", output.String())
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
