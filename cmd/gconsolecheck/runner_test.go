package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeDataSession struct {
	incoming  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	peer      *fakeDataSession
	extra     []byte
	transform func([]byte) []byte
	echo      bool
}

type countedSession struct {
	dataSession
	active *atomic.Int64
	once   sync.Once
}

type writeErrorSession struct {
	dataSession
	err error
}

func (s *writeErrorSession) WriteData(context.Context, []byte) error {
	return s.err
}

func (s *countedSession) Close() {
	s.once.Do(func() {
		s.dataSession.Close()
		s.active.Add(-1)
	})
}

func newFakePair() (*fakeDataSession, *fakeDataSession) {
	left := &fakeDataSession{incoming: make(chan []byte, 32), closed: make(chan struct{})}
	right := &fakeDataSession{incoming: make(chan []byte, 32), closed: make(chan struct{})}
	left.peer = right
	right.peer = left
	return left, right
}

func (s *fakeDataSession) WriteData(ctx context.Context, data []byte) error {
	payload := append([]byte(nil), data...)
	if s.transform != nil {
		payload = s.transform(payload)
	}
	if payload != nil {
		select {
		case s.peer.incoming <- payload:
		case <-ctx.Done():
			return ctx.Err()
		case <-s.closed:
			return io.ErrClosedPipe
		}
	}
	if s.echo {
		select {
		case s.incoming <- append([]byte(nil), data...):
		case <-ctx.Done():
			return ctx.Err()
		case <-s.closed:
			return io.ErrClosedPipe
		}
	}
	return nil
}

func (s *fakeDataSession) ReadData(ctx context.Context, size int) ([]byte, error) {
	result := make([]byte, 0, size)
	for len(result) < size {
		if len(s.extra) > 0 {
			use := min(size-len(result), len(s.extra))
			result = append(result, s.extra[:use]...)
			s.extra = s.extra[use:]
			continue
		}
		select {
		case data := <-s.incoming:
			s.extra = append(s.extra, data...)
		case <-ctx.Done():
			return result, ctx.Err()
		case <-s.closed:
			return result, io.ErrClosedPipe
		}
	}
	return result, nil
}

func (s *fakeDataSession) ReadAvailable(ctx context.Context, duration time.Duration) ([]byte, error) {
	if len(s.extra) > 0 {
		result := append([]byte(nil), s.extra...)
		s.extra = nil
		return result, nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case data := <-s.incoming:
		return data, nil
	case <-timer.C:
		return nil, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, io.ErrClosedPipe
	}
}

func (s *fakeDataSession) Close() {
	s.closeOnce.Do(func() { close(s.closed) })
}

func testConfig() config {
	return config{
		timeout:   time.Second,
		duration:  time.Millisecond,
		extraWait: 10 * time.Millisecond,
		chunkSize: 64,
		seed:      42,
	}
}

func TestAllBytesScenario(t *testing.T) {
	left, right := newFakePair()
	cfg := testConfig()

	verified, err := testAllBytes(context.Background(), cfg, portPair{left: "a", right: "b"}, left, right)

	require.NoError(t, err)
	require.Equal(t, uint64(512), verified)
}

func TestAllBytesScenarioReportsBitFlip(t *testing.T) {
	left, right := newFakePair()
	left.transform = func(data []byte) []byte {
		data[17] ^= 1
		return data
	}

	_, err := testAllBytes(context.Background(), testConfig(), portPair{left: "a", right: "b"}, left, right)

	require.ErrorContains(t, err, "left-to-right mismatch at offset 17")
}

func TestDiscoveryScenario(t *testing.T) {
	left, right := newFakePair()
	cfg := testConfig()
	pair := portPair{left: "ttyS2", right: "ttyS3"}

	verified, err := testDiscovery(context.Background(), cfg, pair, left, right)

	require.NoError(t, err)
	require.Equal(t, uint64(discoveryPayloadSize*2), verified)
}

func TestDiscoveryPayloadContainsFixedSizeSourceMarker(t *testing.T) {
	payload, err := makeDiscoveryPayload(42, "ttyS2", "ttyS3")

	require.NoError(t, err)
	require.Len(t, payload, discoveryPayloadSize)
	marker, err := parseDiscoveryPayload(payload)
	require.NoError(t, err)
	require.Equal(t, discoveryMarker{source: "ttyS2", target: "ttyS3", seed: "42"}, marker)
	require.Contains(t, string(payload), "|test=test_discovery|source=ttyS2|target=ttyS3|seed=42|")
}

func TestDiscoveryComparatorReportsActualSource(t *testing.T) {
	expected, err := makeDiscoveryPayload(42, "ttyS2", "ttyS3")
	require.NoError(t, err)
	actual, err := makeDiscoveryPayload(42, "ttyS7", "ttyS8")
	require.NoError(t, err)

	err = compareDiscoveryPayload("left-to-right", 0, expected, actual)

	require.ErrorContains(t, err, "receiver=ttyS3")
	require.ErrorContains(t, err, "expected_source=ttyS2")
	require.ErrorContains(t, err, "actual_source=ttyS7")
}

func TestOneWayScenarioReportsEcho(t *testing.T) {
	left, right := newFakePair()
	left.echo = true

	_, err := testOneWay(context.Background(), testConfig(), portPair{left: "a", right: "b"}, left, right)

	require.ErrorContains(t, err, "unexpected bytes")
}

func TestMakeOneWayPayloadAddsTestAndConsoleMarkers(t *testing.T) {
	pair := portPair{left: "ttyS2", right: "ttyS3"}
	payload := makeOneWayPayload(42, pair, pair.left, pair.right, "one-way-left")
	begin := []byte("|test=test_one_way|source=ttyS2|target=ttyS3|BEGIN|")
	end := []byte("|test=test_one_way|source=ttyS2|target=ttyS3|END|")

	require.Equal(t, begin, payload[:len(begin)])
	require.Equal(t, end, payload[len(payload)-len(end):])
	require.Len(t, payload, len(begin)+oneWayPayloadSize+len(end))
}

func TestMakeOneWayPayloadReversesConsoleMarkers(t *testing.T) {
	pair := portPair{left: "ttyS2", right: "ttyS3"}
	payload := makeOneWayPayload(42, pair, pair.right, pair.left, "one-way-right")

	require.Contains(t, string(payload[:80]), "|source=ttyS3|target=ttyS2|BEGIN|")
	require.Contains(t, string(payload[len(payload)-80:]), "|source=ttyS3|target=ttyS2|END|")
}

func TestExchangeTimesOutOnDroppedData(t *testing.T) {
	left, right := newFakePair()
	left.transform = func(data []byte) []byte { return data[:4] }

	err := exchange(context.Background(), 20*time.Millisecond, left, right, []byte("payload"), nil, "test", 0)

	require.ErrorContains(t, err, "length mismatch at offset 4")
	require.ErrorContains(t, err, "expected 7 bytes, got 4")
	require.ErrorContains(t, err, "read error after 4/7 bytes")
	require.ErrorContains(t, err, "payload diff:")
	require.ErrorContains(t, err, "offset   | written_ascii    | read_ascii")
	require.ErrorContains(t, err, "70 61 79 6c 6f 61 64")
	require.ErrorContains(t, err, "70 61 79 6c \x1b[31m--\x1b[0m")
	require.ErrorContains(t, err, "payl\x1b[31m-\x1b[0m")
}

func TestExchangeSplitsLargePayload(t *testing.T) {
	left, right := newFakePair()
	var maximumWrite atomic.Int64
	left.transform = func(data []byte) []byte {
		for {
			previous := maximumWrite.Load()
			if int64(len(data)) <= previous || maximumWrite.CompareAndSwap(previous, int64(len(data))) {
				break
			}
		}
		return data
	}
	payload := make([]byte, transportChunkSize*3+1)

	err := exchange(context.Background(), time.Second, left, right, payload, nil, "test", 0)

	require.NoError(t, err)
	require.Equal(t, int64(transportChunkSize), maximumWrite.Load())
}

func TestExchangeChunkPreservesPrimaryErrorDuringCancellation(t *testing.T) {
	left, right := newFakePair()
	primaryErr := errors.New("primary write failure")
	leftWithError := &writeErrorSession{dataSession: left, err: primaryErr}

	err := exchangeChunk(context.Background(), time.Second, leftWithError, right, []byte("left"), []byte("right"), "test", 0)

	require.ErrorContains(t, err, "test write on left: primary write failure")
	require.NotErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestRunAllPairsContinuesAfterConnectionFailure(t *testing.T) {
	goodLeft, goodRight := newFakePair()
	sessions := map[string]dataSession{"good-left": goodLeft, "good-right": goodRight}
	factory := func(_ context.Context, port string) (dataSession, error) {
		session, ok := sessions[port]
		if !ok {
			return nil, errors.New("connection failed")
		}
		return session, nil
	}
	cfg := testConfig()
	cfg.pairs = []portPair{{left: "bad-left", right: "bad-right"}, {left: "good-left", right: "good-right"}}
	cfg.scenarios = []string{"test_all_bytes"}

	var output bytes.Buffer
	results := runAllPairs(context.Background(), cfg, factory, &output)

	require.Len(t, results, 2)
	require.False(t, results[0].passed)
	require.True(t, results[1].passed)
	require.Contains(t, output.String(), "time_to_connect=")
}

func TestRunAllPairsLimitsParallelPairs(t *testing.T) {
	sessions := make(map[string]dataSession)
	for index := 0; index < 3; index++ {
		left, right := newFakePair()
		sessions[fmt.Sprintf("left-%d", index)] = left
		sessions[fmt.Sprintf("right-%d", index)] = right
	}
	var active atomic.Int64
	var maximum atomic.Int64
	factory := func(_ context.Context, port string) (dataSession, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		return &countedSession{dataSession: sessions[port], active: &active}, nil
	}
	cfg := testConfig()
	cfg.parallel = 1
	cfg.scenarios = []string{"test_all_bytes"}
	for index := 0; index < 3; index++ {
		cfg.pairs = append(cfg.pairs, portPair{left: fmt.Sprintf("left-%d", index), right: fmt.Sprintf("right-%d", index)})
	}

	results := runAllPairs(context.Background(), cfg, factory, io.Discard)

	require.Len(t, results, 3)
	for _, result := range results {
		require.True(t, result.passed)
	}
	require.Equal(t, int64(2), maximum.Load())
	require.Zero(t, active.Load())
}

func TestDeterministicPayloadDependsOnPairAndDirection(t *testing.T) {
	pair := portPair{left: "a", right: "b"}
	first := makeDeterministicPayload(42, pair, "left", 64)
	second := makeDeterministicPayload(42, pair, "left", 64)
	otherDirection := makeDeterministicPayload(42, pair, "right", 64)
	otherPair := makeDeterministicPayload(42, portPair{left: "c", right: "d"}, "left", 64)

	require.Equal(t, first, second)
	require.NotEqual(t, first, otherDirection)
	require.NotEqual(t, first, otherPair)
}

func TestMakeSoakPayloadAddsIterationAndDirectionMarker(t *testing.T) {
	leftGenerator := newByteGenerator(42)
	rightGenerator := newByteGenerator(42)

	left := makeSoakPayload(leftGenerator, 17, "L", 32)
	right := makeSoakPayload(rightGenerator, 17, "R", 32)

	require.Equal(t, []byte("iter_17_dir_L\n"), left[:len("iter_17_dir_L\n")])
	require.Equal(t, []byte("iter_17_dir_R\n"), right[:len("iter_17_dir_R\n")])
	require.Len(t, left, len("iter_17_dir_L\n")+32)
	require.Len(t, right, len("iter_17_dir_R\n")+32)
	require.Equal(t, left[len("iter_17_dir_L\n"):], right[len("iter_17_dir_R\n"):])
}

func TestMakeASCIISoakPayloadUsesOnlyPrintableCharacters(t *testing.T) {
	generator := newByteGenerator(42)

	payload := makeASCIISoakPayload(generator, 17, "L", 4096)

	require.Equal(t, []byte("|iter_17_dir_L|"), payload[:len("|iter_17_dir_L|")])
	for index, value := range payload {
		require.GreaterOrEqualf(t, value, byte(0x20), "byte %d is not printable", index)
		require.LessOrEqualf(t, value, byte(0x7e), "byte %d is not printable", index)
	}
}

func TestFormatPayloadDiffShowsChangedRanges(t *testing.T) {
	diff := formatPayloadDiff(100, []byte("prefix-expected-suffix"), []byte("prefix-actual-suffix"))

	require.Contains(t, diff, "first_difference_offset=107")
	require.Contains(t, diff, "common_prefix=7")
	require.Contains(t, diff, "common_suffix=7")
	require.Contains(t, diff, "offset   | written_ascii    | read_ascii")
	require.Contains(t, diff, "00000064 | prefix-expected-")
	require.Contains(t, diff, "70 72 65 66 69 78 2d 65 78 70 65 63 74 65 64 2d")
	require.Contains(t, diff, "\x1b[31m61\x1b[0m")
	require.Contains(t, diff, "prefix-\x1b[31ma\x1b[0m")
}

func TestIsEncryptionRequired(t *testing.T) {
	require.True(t, isEncryptionRequired(errors.New("unable to login: encryption required\r\n")))
	require.False(t, isEncryptionRequired(errors.New("authentication failed")))
	require.False(t, isEncryptionRequired(nil))
}
