package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	oneWayPayloadSize    = 1024
	transportChunkSize   = 256
	discoveryPayloadSize = 128
)

type sessionFactory func(context.Context, string) (dataSession, error)

type scenarioStats struct {
	bytesVerified uint64
	started       time.Time
	finished      time.Time
}

func (s scenarioStats) duration() time.Duration {
	return s.finished.Sub(s.started)
}

type pairResult struct {
	pair          portPair
	passed        bool
	bytesVerified uint64
	connectTime   time.Duration
	err           error
}

type reporter struct {
	mu sync.Mutex
	w  io.Writer
}

func (r *reporter) scenarioPassed(pair portPair, scenario string, connectTime time.Duration, stats scenarioStats) {
	r.mu.Lock()
	defer r.mu.Unlock()
	duration := stats.duration()
	rate := float64(stats.bytesVerified)
	if duration > 0 {
		rate /= duration.Seconds()
	}
	fmt.Fprintf(r.w, "PASS pair=%s scenario=%s time_to_connect=%s bytes=%d duration=%s rate=%.0fB/s\n",
		pair, scenario, connectTime.Round(time.Millisecond), stats.bytesVerified, duration.Round(time.Millisecond), rate)
}

func (r *reporter) pairFailed(pair portPair, scenario string, connectTime time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if scenario == "" {
		fmt.Fprintf(r.w, "FAIL pair=%s stage=connect time_to_connect=%s error=%v\n", pair, connectTime.Round(time.Millisecond), err)
		return
	}
	fmt.Fprintf(r.w, "FAIL pair=%s scenario=%s time_to_connect=%s error=%v\n", pair, scenario, connectTime.Round(time.Millisecond), err)
}

func runAllPairs(ctx context.Context, cfg config, factory sessionFactory, output io.Writer) []pairResult {
	rep := &reporter{w: output}
	results := make([]pairResult, len(cfg.pairs))
	parallel := cfg.parallel
	if parallel == 0 || parallel > len(cfg.pairs) {
		parallel = len(cfg.pairs)
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range parallel {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				pair := cfg.pairs[index]
				results[index] = runPair(ctx, cfg, pair, factory, rep)
			}
		}()
	}
	for index := range cfg.pairs {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	return results
}

func runPair(ctx context.Context, cfg config, pair portPair, factory sessionFactory, rep *reporter) pairResult {
	result := pairResult{pair: pair}
	connectStarted := time.Now()
	var left, right dataSession
	var group errgroup.Group
	group.Go(func() error {
		var err error
		left, err = factory(ctx, pair.left)
		if err != nil {
			return fmt.Errorf("connect %s: %w", pair.left, err)
		}
		return nil
	})
	group.Go(func() error {
		var err error
		right, err = factory(ctx, pair.right)
		if err != nil {
			return fmt.Errorf("connect %s: %w", pair.right, err)
		}
		return nil
	})
	connectErr := group.Wait()
	result.connectTime = time.Since(connectStarted)
	if connectErr != nil {
		closeSessions(left, right)
		result.err = connectErr
		rep.pairFailed(pair, "", result.connectTime, connectErr)
		return result
	}
	defer closeSessions(left, right)

	stopWatcher := closeSessionsOnDone(ctx, left, right)
	defer stopWatcher()

	for _, scenarioName := range cfg.scenarios {
		stats, err := runScenario(ctx, cfg, pair, scenarioName, left, right)
		result.bytesVerified += stats.bytesVerified
		if err != nil {
			result.err = err
			rep.pairFailed(pair, scenarioName, result.connectTime, err)
			return result
		}
		rep.scenarioPassed(pair, scenarioName, result.connectTime, stats)
	}
	result.passed = true
	return result
}

func closeSessions(sessions ...dataSession) {
	for _, session := range sessions {
		if session != nil {
			session.Close()
		}
	}
}

func closeSessionsOnDone(ctx context.Context, sessions ...dataSession) func() {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			closeSessions(sessions...)
		case <-done:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
}

func runScenario(ctx context.Context, cfg config, pair portPair, name string, left, right dataSession) (scenarioStats, error) {
	stats := scenarioStats{started: time.Now()}
	var err error
	switch name {
	case "test_one_way":
		stats.bytesVerified, err = testOneWay(ctx, cfg, pair, left, right)
	case "test_all_bytes":
		stats.bytesVerified, err = testAllBytes(ctx, cfg, pair, left, right)
	case "test_random_soak":
		stats.bytesVerified, err = testRandomSoak(ctx, cfg, pair, left, right)
	case "test_random_soak_ascii":
		stats.bytesVerified, err = testRandomSoakASCII(ctx, cfg, pair, left, right)
	case "test_discovery":
		stats.bytesVerified, err = testDiscovery(ctx, cfg, pair, left, right)
	default:
		err = fmt.Errorf("unknown scenario %q", name)
	}
	stats.finished = time.Now()
	return stats, err
}

func testOneWay(ctx context.Context, cfg config, pair portPair, left, right dataSession) (uint64, error) {
	leftPayload := makeOneWayPayload(cfg.seed, pair, pair.left, pair.right, "one-way-left")
	if err := exchange(ctx, cfg.timeout, left, right, leftPayload, nil, "left-to-right", 0); err != nil {
		return 0, err
	}
	if err := assertQuiet(ctx, cfg.timeout, cfg.extraWait, left, right); err != nil {
		return 0, fmt.Errorf("left-to-right quiet check: %w", err)
	}

	rightPayload := makeOneWayPayload(cfg.seed, pair, pair.right, pair.left, "one-way-right")
	if err := exchange(ctx, cfg.timeout, left, right, nil, rightPayload, "right-to-left", 0); err != nil {
		return uint64(len(leftPayload)), err
	}
	if err := assertQuiet(ctx, cfg.timeout, cfg.extraWait, left, right); err != nil {
		return uint64(len(leftPayload)), fmt.Errorf("right-to-left quiet check: %w", err)
	}
	return uint64(len(leftPayload) + len(rightPayload)), nil
}

func makeOneWayPayload(seed uint64, pair portPair, source, target, generatorLabel string) []byte {
	begin := []byte(fmt.Sprintf("|test=test_one_way|source=%s|target=%s|BEGIN|", source, target))
	end := []byte(fmt.Sprintf("|test=test_one_way|source=%s|target=%s|END|", source, target))
	body := makeDeterministicPayload(seed, pair, generatorLabel, oneWayPayloadSize)
	payload := make([]byte, 0, len(begin)+len(body)+len(end))
	payload = append(payload, begin...)
	payload = append(payload, body...)
	payload = append(payload, end...)
	return payload
}

func testAllBytes(ctx context.Context, cfg config, pair portPair, left, right dataSession) (uint64, error) {
	leftPayload := make([]byte, 256)
	rightPayload := make([]byte, 256)
	for index := range leftPayload {
		leftPayload[index] = byte(index)
		rightPayload[index] = byte(255 - index)
	}
	if err := exchange(ctx, cfg.timeout, left, right, leftPayload, rightPayload, "full-duplex", 0); err != nil {
		return 0, err
	}
	if err := assertQuiet(ctx, cfg.timeout, cfg.extraWait, left, right); err != nil {
		return uint64(len(leftPayload) + len(rightPayload)), fmt.Errorf("quiet check: %w", err)
	}
	return uint64(len(leftPayload) + len(rightPayload)), nil
}

func testDiscovery(ctx context.Context, cfg config, pair portPair, left, right dataSession) (uint64, error) {
	leftPayload, err := makeDiscoveryPayload(cfg.seed, pair.left, pair.right)
	if err != nil {
		return 0, err
	}
	rightPayload, err := makeDiscoveryPayload(cfg.seed, pair.right, pair.left)
	if err != nil {
		return 0, err
	}
	if err := exchangeChunkWithComparator(ctx, cfg.timeout, left, right, leftPayload, rightPayload, "discovery", 0, compareDiscoveryPayload); err != nil {
		return 0, err
	}
	if err := assertQuiet(ctx, cfg.timeout, cfg.extraWait, left, right); err != nil {
		return uint64(len(leftPayload) + len(rightPayload)), fmt.Errorf("discovery extra-data check: %w", err)
	}
	return uint64(len(leftPayload) + len(rightPayload)), nil
}

type discoveryMarker struct {
	source string
	target string
	seed   string
}

func makeDiscoveryPayload(seed uint64, source, target string) ([]byte, error) {
	marker := fmt.Sprintf("|test=test_discovery|source=%s|target=%s|seed=%d|", source, target, seed)
	if len(marker) > discoveryPayloadSize {
		return nil, fmt.Errorf("discovery marker for %s -> %s is %d bytes, maximum is %d", source, target, len(marker), discoveryPayloadSize)
	}
	payload := bytes.Repeat([]byte{' '}, discoveryPayloadSize)
	copy(payload, marker)
	return payload, nil
}

func parseDiscoveryPayload(payload []byte) (discoveryMarker, error) {
	text := strings.TrimSpace(string(payload))
	fields := make(map[string]string)
	for _, part := range strings.Split(strings.Trim(text, "|"), "|") {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			fields[key] = value
		}
	}
	if fields["test"] != "test_discovery" || fields["source"] == "" || fields["target"] == "" {
		return discoveryMarker{}, fmt.Errorf("invalid discovery marker %q", text)
	}
	return discoveryMarker{source: fields["source"], target: fields["target"], seed: fields["seed"]}, nil
}

func compareDiscoveryPayload(direction string, baseOffset uint64, expected, actual []byte) error {
	if bytes.Equal(expected, actual) {
		return nil
	}
	expectedMarker, expectedErr := parseDiscoveryPayload(expected)
	if expectedErr != nil {
		return fmt.Errorf("invalid expected discovery marker: %w", expectedErr)
	}
	actualMarker, actualErr := parseDiscoveryPayload(actual)
	if actualErr != nil {
		return fmt.Errorf("discovery mismatch receiver=%s expected_source=%s marker_not_received=true: %v\n%s",
			expectedMarker.target, expectedMarker.source, actualErr, formatPayloadDiff(baseOffset, expected, actual))
	}
	return fmt.Errorf("discovery mismatch receiver=%s expected_source=%s actual_source=%s actual_target=%s expected_seed=%s actual_seed=%s direction=%s\n%s",
		expectedMarker.target, expectedMarker.source, actualMarker.source, actualMarker.target,
		expectedMarker.seed, actualMarker.seed, direction, formatPayloadDiff(baseOffset, expected, actual))
}

func testRandomSoak(ctx context.Context, cfg config, pair portPair, left, right dataSession) (uint64, error) {
	return testRandomSoakWithPayload(ctx, cfg, pair, left, right, makeSoakPayload)
}

func testRandomSoakASCII(ctx context.Context, cfg config, pair portPair, left, right dataSession) (uint64, error) {
	return testRandomSoakWithPayload(ctx, cfg, pair, left, right, makeASCIISoakPayload)
}

type soakPayloadFactory func(*byteGenerator, uint64, string, int) []byte

func testRandomSoakWithPayload(ctx context.Context, cfg config, pair portPair, left, right dataSession, makePayload soakPayloadFactory) (uint64, error) {
	leftGenerator := newByteGenerator(deriveSeed(cfg.seed, pair, "soak-left"))
	rightGenerator := newByteGenerator(deriveSeed(cfg.seed, pair, "soak-right"))
	deadline := time.Now().Add(cfg.duration)
	var verified uint64
	var streamOffset uint64
	for chunk := uint64(0); ; chunk++ {
		if chunk > 0 && !time.Now().Before(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return verified, ctx.Err()
		default:
		}
		leftPayload := makePayload(leftGenerator, chunk, "L", cfg.chunkSize)
		rightPayload := makePayload(rightGenerator, chunk, "R", cfg.chunkSize)
		label := fmt.Sprintf("full-duplex iter_%d", chunk)
		if err := exchange(ctx, cfg.timeout, left, right, leftPayload, rightPayload, label, streamOffset); err != nil {
			return verified, fmt.Errorf("chunk %d: %w", chunk, err)
		}
		verified += uint64(len(leftPayload) + len(rightPayload))
		streamOffset += uint64(len(leftPayload))
		if err := assertQuiet(ctx, cfg.timeout, cfg.extraWait, left, right); err != nil {
			return verified, fmt.Errorf("chunk %d extra-data check: %w", chunk, err)
		}
	}
	return verified, nil
}

func makeSoakPayload(generator *byteGenerator, iteration uint64, direction string, randomSize int) []byte {
	marker := []byte(fmt.Sprintf("iter_%d_dir_%s\n", iteration, direction))
	payload := make([]byte, len(marker)+randomSize)
	copy(payload, marker)
	generator.Fill(payload[len(marker):])
	return payload
}

func makeASCIISoakPayload(generator *byteGenerator, iteration uint64, direction string, randomSize int) []byte {
	marker := []byte(fmt.Sprintf("|iter_%d_dir_%s|", iteration, direction))
	payload := make([]byte, len(marker)+randomSize)
	copy(payload, marker)
	generator.FillPrintable(payload[len(marker):])
	return payload
}

func exchange(ctx context.Context, timeout time.Duration, left, right dataSession, leftPayload, rightPayload []byte, label string, baseOffset uint64) error {
	for offset := 0; offset < len(leftPayload) || offset < len(rightPayload); offset += transportChunkSize {
		leftEnd := min(offset+transportChunkSize, len(leftPayload))
		rightEnd := min(offset+transportChunkSize, len(rightPayload))
		var leftChunk, rightChunk []byte
		if offset < len(leftPayload) {
			leftChunk = leftPayload[offset:leftEnd]
		}
		if offset < len(rightPayload) {
			rightChunk = rightPayload[offset:rightEnd]
		}
		if err := exchangeChunk(ctx, timeout, left, right, leftChunk, rightChunk, label, baseOffset+uint64(offset)); err != nil {
			return err
		}
	}
	return nil
}

func exchangeChunk(ctx context.Context, timeout time.Duration, left, right dataSession, leftPayload, rightPayload []byte, label string, baseOffset uint64) error {
	return exchangeChunkWithComparator(ctx, timeout, left, right, leftPayload, rightPayload, label, baseOffset, comparePayload)
}

type payloadComparator func(string, uint64, []byte, []byte) error

func exchangeChunkWithComparator(ctx context.Context, timeout time.Duration, left, right dataSession, leftPayload, rightPayload []byte, label string, baseOffset uint64, comparator payloadComparator) error {
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	var group errgroup.Group
	var firstErr error
	var firstErrOnce sync.Once
	stopWatcher := closeSessionsOnDone(opCtx, left, right)
	defer stopWatcher()
	groupGo := func(task func() error) {
		group.Go(func() error {
			err := task()
			if err != nil {
				firstErrOnce.Do(func() {
					// Store the original failure before cancellation wakes the
					// other goroutines with secondary context/closed-connection
					// errors.
					firstErr = err
					cancel()
				})
			}
			return nil
		})
	}

	if len(rightPayload) > 0 {
		groupGo(func() error {
			actual, err := left.ReadData(opCtx, len(rightPayload))
			return compareReadResult(label+" read on left", "right-to-left", baseOffset, rightPayload, actual, err, comparator)
		})
		groupGo(func() error {
			if err := right.WriteData(opCtx, rightPayload); err != nil {
				return fmt.Errorf("%s write on right: %w", label, err)
			}
			return nil
		})
	}
	if len(leftPayload) > 0 {
		groupGo(func() error {
			actual, err := right.ReadData(opCtx, len(leftPayload))
			return compareReadResult(label+" read on right", "left-to-right", baseOffset, leftPayload, actual, err, comparator)
		})
		groupGo(func() error {
			if err := left.WriteData(opCtx, leftPayload); err != nil {
				return fmt.Errorf("%s write on left: %w", label, err)
			}
			return nil
		})
	}
	_ = group.Wait()
	stopWatcher()
	cancel()
	return firstErr
}

func compareReadResult(operation, direction string, baseOffset uint64, expected, actual []byte, readErr error, comparator payloadComparator) error {
	compareErr := comparator(direction, baseOffset, expected, actual)
	if readErr == nil {
		return compareErr
	}
	if compareErr != nil {
		return fmt.Errorf("%s: %w; read error after %d/%d bytes: %v", operation, compareErr, len(actual), len(expected), readErr)
	}
	return fmt.Errorf("%s after %d/%d bytes: %w", operation, len(actual), len(expected), readErr)
}

func comparePayload(direction string, baseOffset uint64, expected, actual []byte) error {
	if bytes.Equal(expected, actual) {
		return nil
	}
	limit := min(len(expected), len(actual))
	for index := 0; index < limit; index++ {
		if expected[index] != actual[index] {
			return fmt.Errorf("%s mismatch at offset %d: expected 0x%02x, got 0x%02x\n%s",
				direction, baseOffset+uint64(index), expected[index], actual[index], formatPayloadDiff(baseOffset, expected, actual))
		}
	}
	return fmt.Errorf("%s length mismatch at offset %d: expected %d bytes, got %d\n%s",
		direction, baseOffset+uint64(limit), len(expected), len(actual), formatPayloadDiff(baseOffset, expected, actual))
}

func formatPayloadDiff(baseOffset uint64, expected, actual []byte) string {
	prefix := 0
	for prefix < len(expected) && prefix < len(actual) && expected[prefix] == actual[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(expected)-prefix && suffix < len(actual)-prefix &&
		expected[len(expected)-1-suffix] == actual[len(actual)-1-suffix] {
		suffix++
	}
	expectedEnd := len(expected) - suffix
	actualEnd := len(actual) - suffix
	var result strings.Builder
	fmt.Fprintf(&result,
		"payload diff: first_difference_offset=%d local_offset=%d common_prefix=%d common_suffix=%d\n",
		baseOffset+uint64(prefix), prefix, prefix, suffix,
	)
	result.WriteString("  offset   | written_ascii    | read_ascii       | written_hex                                     | read_hex\n")
	start := prefix / 16 * 16
	diffEnd := max(expectedEnd, actualEnd)
	end := min(max(len(expected), len(actual)), (diffEnd+31)/16*16)
	if end <= start {
		end = min(max(len(expected), len(actual)), start+16)
	}
	for offset := start; offset < end; offset += 16 {
		fmt.Fprintf(&result, "  %08x | %s | %s | %-47s | %s\n",
			baseOffset+uint64(offset), formatASCIIColumn(expected, offset), formatReadASCIIColumn(expected, actual, offset),
			formatHexColumn(expected, offset), formatReadHexColumn(expected, actual, offset))
	}
	return strings.TrimSuffix(result.String(), "\n")
}

func formatASCIIColumn(data []byte, offset int) string {
	var result strings.Builder
	for index := 0; index < 16; index++ {
		position := offset + index
		if position >= len(data) {
			result.WriteByte(' ')
			continue
		}
		value := data[position]
		if value >= 0x20 && value <= 0x7e {
			result.WriteByte(value)
		} else {
			result.WriteByte('.')
		}
	}
	return result.String()
}

func formatHexColumn(data []byte, offset int) string {
	values := make([]string, 0, 16)
	for index := 0; index < 16; index++ {
		position := offset + index
		if position >= len(data) {
			values = append(values, "  ")
		} else {
			values = append(values, fmt.Sprintf("%02x", data[position]))
		}
	}
	return strings.Join(values, " ")
}

func formatReadASCIIColumn(expected, actual []byte, offset int) string {
	const (
		red   = "\x1b[31m"
		reset = "\x1b[0m"
	)
	var result strings.Builder
	for index := 0; index < 16; index++ {
		position := offset + index
		if position >= len(expected) && position >= len(actual) {
			result.WriteByte(' ')
			continue
		}
		if position >= len(actual) {
			result.WriteString(red + "-" + reset)
			continue
		}
		value := actual[position]
		character := byte('.')
		if value >= 0x20 && value <= 0x7e {
			character = value
		}
		if position >= len(expected) || actual[position] != expected[position] {
			result.WriteString(red)
			result.WriteByte(character)
			result.WriteString(reset)
		} else {
			result.WriteByte(character)
		}
	}
	return result.String()
}

func formatReadHexColumn(expected, actual []byte, offset int) string {
	const (
		red   = "\x1b[31m"
		reset = "\x1b[0m"
	)
	values := make([]string, 0, 16)
	for index := 0; index < 16; index++ {
		position := offset + index
		if position >= len(expected) && position >= len(actual) {
			values = append(values, "  ")
			continue
		}
		if position >= len(actual) {
			values = append(values, red+"--"+reset)
			continue
		}
		value := fmt.Sprintf("%02x", actual[position])
		if position >= len(expected) || actual[position] != expected[position] {
			value = red + value + reset
		}
		values = append(values, value)
	}
	return strings.Join(values, " ")
}

func assertQuiet(ctx context.Context, timeout, window time.Duration, sessions ...dataSession) error {
	if timeout <= window {
		window = timeout / 2
	}
	if window <= 0 {
		return errors.New("quiet window is not positive")
	}
	group, groupCtx := errgroup.WithContext(ctx)
	for index, session := range sessions {
		index, session := index, session
		group.Go(func() error {
			data, err := session.ReadAvailable(groupCtx, window)
			if err != nil {
				return fmt.Errorf("port side %d: %w", index, err)
			}
			if len(data) != 0 {
				return fmt.Errorf("port side %d received %d unexpected bytes: %x", index, len(data), data[:min(len(data), 32)])
			}
			return nil
		})
	}
	return group.Wait()
}

func deriveSeed(seed uint64, pair portPair, label string) uint64 {
	hash := fnv.New64a()
	_, _ = fmt.Fprintf(hash, "%d\x00%s\x00%s\x00%s", seed, pair.left, pair.right, label)
	result := hash.Sum64()
	if result == 0 {
		return 0x9e3779b97f4a7c15
	}
	return result
}

func makeDeterministicPayload(seed uint64, pair portPair, label string, size int) []byte {
	result := make([]byte, size)
	newByteGenerator(deriveSeed(seed, pair, label)).Fill(result)
	return result
}

type byteGenerator struct {
	state uint64
}

func newByteGenerator(seed uint64) *byteGenerator {
	if seed == 0 {
		seed = 0x9e3779b97f4a7c15
	}
	return &byteGenerator{state: seed}
}

func (g *byteGenerator) Fill(data []byte) {
	for index := range data {
		data[index] = g.nextByte()
	}
}

func (g *byteGenerator) FillPrintable(data []byte) {
	const printableCount = 0x7e - 0x20 + 1
	for index := range data {
		data[index] = 0x20 + g.nextByte()%printableCount
	}
}

func (g *byteGenerator) nextByte() byte {
	g.state ^= g.state << 13
	g.state ^= g.state >> 7
	g.state ^= g.state << 17
	return byte(g.state >> 56)
}
