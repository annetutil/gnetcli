package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/annetutil/gnetcli/pkg/streamer/console"
)

const allPortsDiscoveryPayloadSize = 128

type allPortsMarker struct {
	source string
	runID  string
}

type allPortsState struct {
	name        string
	info        console.CommandInfoPort
	session     dataSession
	connectTime time.Duration
	connectErr  error
	writeErr    error
	readData    []byte
	readErr     error
	marker      allPortsMarker
	markerErr   error
}

func runDiscoveryAllPorts(ctx context.Context, cfg config, factory sessionFactory, discover portsDiscovery, output io.Writer) error {
	ports, err := discover(ctx)
	if err != nil {
		return fmt.Errorf("list conserver ports: %w", err)
	}
	names := make([]string, 0, len(ports))
	for name := range ports {
		names = append(names, name)
	}
	sort.Slice(names, func(left, right int) bool {
		return consolePortLess(names[left], names[right])
	})
	if len(names) == 0 {
		return fmt.Errorf("conserver returned no ports")
	}

	states := make([]allPortsState, len(names))
	parallel := cfg.parallel
	if parallel == 0 || parallel > len(names) {
		parallel = len(names)
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				name := names[index]
				states[index] = allPortsState{name: name, info: ports[name]}
				if ports[name].GetPCLwr() != "" {
					continue
				}
				started := time.Now()
				states[index].session, states[index].connectErr = factory(ctx, name)
				states[index].connectTime = time.Since(started)
			}
		}()
	}
	for index := range names {
		jobs <- index
	}
	close(jobs)
	workers.Wait()

	sessions := make([]dataSession, 0, len(states))
	for index := range states {
		state := &states[index]
		switch {
		case state.info.GetPCLwr() != "":
			fmt.Fprintf(output, "DISCOVERY BUSY port=%s writer=%s\n", state.name, state.info.GetPCLwr())
		case state.connectErr != nil:
			fmt.Fprintf(output, "DISCOVERY PORT_ERROR port=%s stage=connect time_to_connect=%s error=%v\n", state.name, state.connectTime.Round(time.Millisecond), state.connectErr)
		case state.session != nil:
			sessions = append(sessions, state.session)
		}
	}
	defer closeSessions(sessions...)
	if len(sessions) == 0 {
		fmt.Fprintf(output, "DISCOVERY_SUMMARY ports=%d connected=0 pairs=0 unpaired=0 busy=%d errors=%d\n",
			len(states), countBusy(states), countConnectErrors(states))
		return nil
	}

	runID := fmt.Sprintf("%x", time.Now().UnixNano())
	opCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	stopWatcher := closeSessionsOnDone(opCtx, sessions...)
	var exchange sync.WaitGroup
	for index := range states {
		state := &states[index]
		if state.session == nil {
			continue
		}
		payload, payloadErr := makeAllPortsDiscoveryPayload(state.name, runID)
		if payloadErr != nil {
			state.writeErr = payloadErr
			continue
		}
		exchange.Add(2)
		go func() {
			defer exchange.Done()
			state.readData, state.readErr = state.session.ReadData(opCtx, allPortsDiscoveryPayloadSize)
		}()
		go func() {
			defer exchange.Done()
			state.writeErr = state.session.WriteData(opCtx, payload)
		}()
	}
	exchange.Wait()
	stopWatcher()
	cancel()

	mapping := make(map[string]string)
	unpaired := 0
	errorsCount := countConnectErrors(states)
	for index := range states {
		state := &states[index]
		if state.session == nil {
			continue
		}
		if state.writeErr != nil {
			fmt.Fprintf(output, "DISCOVERY PORT_ERROR port=%s stage=write error=%v\n", state.name, state.writeErr)
			errorsCount++
		}
		state.marker, state.markerErr = parseAllPortsDiscoveryPayload(state.readData)
		if state.markerErr != nil {
			reportUnpairedDiscoveryPort(output, state)
			unpaired++
			continue
		}
		if state.marker.runID != runID {
			fmt.Fprintf(output, "DISCOVERY UNPAIRED port=%s stale_marker=true source=%s expected_run=%s actual_run=%s\n",
				state.name, state.marker.source, runID, state.marker.runID)
			unpaired++
			continue
		}
		mapping[state.name] = state.marker.source
		reportDiscoveryReceived(output, state)
	}

	pairs := 0
	reported := make(map[string]struct{})
	for _, receiver := range names {
		source, ok := mapping[receiver]
		if !ok {
			continue
		}
		if source == receiver {
			fmt.Fprintf(output, "DISCOVERY SELF_LOOP port=%s\n", receiver)
			unpaired++
			continue
		}
		reverse, reverseOK := mapping[source]
		if reverseOK && reverse == receiver {
			left, right := receiver, source
			if consolePortLess(right, left) {
				left, right = right, left
			}
			key := left + "=" + right
			if _, ok := reported[key]; !ok {
				reported[key] = struct{}{}
				pairs++
				fmt.Fprintf(output, "DISCOVERED left=%s right=%s\n", left, right)
			}
			continue
		}
		fmt.Fprintf(output, "DISCOVERY MISMATCH receiver=%s source=%s reverse_source=%s\n", receiver, source, reverse)
		unpaired++
	}

	fmt.Fprintf(output, "DISCOVERY_SUMMARY ports=%d connected=%d pairs=%d unpaired=%d busy=%d errors=%d run_id=%s\n",
		len(states), len(sessions), pairs, unpaired, countBusy(states), errorsCount, runID)
	return nil
}

func consolePortLess(left, right string) bool {
	leftPrefix, leftNumber, leftOK := splitConsolePortNumber(left)
	rightPrefix, rightNumber, rightOK := splitConsolePortNumber(right)
	if leftOK && rightOK && leftPrefix == rightPrefix && leftNumber != rightNumber {
		return leftNumber < rightNumber
	}
	return left < right
}

func splitConsolePortNumber(value string) (string, int, bool) {
	index := len(value)
	for index > 0 && value[index-1] >= '0' && value[index-1] <= '9' {
		index--
	}
	if index == len(value) {
		return value, 0, false
	}
	number, err := strconv.Atoi(value[index:])
	if err != nil {
		return value, 0, false
	}
	return value[:index], number, true
}

func reportDiscoveryReceived(output io.Writer, state *allPortsState) {
	if state.readErr == nil && len(state.readData) == allPortsDiscoveryPayloadSize {
		fmt.Fprintf(output, "DISCOVERY RECEIVED receiver=%s source=%s\n", state.name, state.marker.source)
		return
	}
	fmt.Fprintf(output, "DISCOVERY RECEIVED receiver=%s source=%s bytes=%d read_error=%v\n",
		state.name, state.marker.source, len(state.readData), state.readErr)
}

func reportUnpairedDiscoveryPort(output io.Writer, state *allPortsState) {
	if len(state.readData) == 0 {
		fmt.Fprintf(output, "DISCOVERY UNPAIRED port=%s reason=empty_read\n", state.name)
		return
	}
	fmt.Fprintf(output, "DISCOVERY UNPAIRED port=%s marker_not_received=true bytes=%d read_error=%v marker_error=%v\n",
		state.name, len(state.readData), state.readErr, state.markerErr)
}

func makeAllPortsDiscoveryPayload(source, runID string) ([]byte, error) {
	marker := fmt.Sprintf("|test=test_discovery_all_ports|source=%s|run=%s|", source, runID)
	if len(marker) > allPortsDiscoveryPayloadSize {
		return nil, fmt.Errorf("all-ports discovery marker for %s is %d bytes, maximum is %d", source, len(marker), allPortsDiscoveryPayloadSize)
	}
	payload := bytes.Repeat([]byte{' '}, allPortsDiscoveryPayloadSize)
	copy(payload, marker)
	for index, value := range payload {
		if value < 0x20 || value > 0x7e {
			return nil, fmt.Errorf("all-ports discovery payload contains control byte 0x%02x at offset %d", value, index)
		}
	}
	return payload, nil
}

func parseAllPortsDiscoveryPayload(payload []byte) (allPortsMarker, error) {
	text := strings.TrimSpace(string(payload))
	fields := make(map[string]string)
	for _, part := range strings.Split(strings.Trim(text, "|"), "|") {
		key, value, ok := strings.Cut(part, "=")
		if ok {
			fields[key] = value
		}
	}
	if fields["test"] != "test_discovery_all_ports" || fields["source"] == "" || fields["run"] == "" {
		return allPortsMarker{}, fmt.Errorf("invalid all-ports discovery marker %q", text)
	}
	return allPortsMarker{source: fields["source"], runID: fields["run"]}, nil
}

func countBusy(states []allPortsState) int {
	count := 0
	for _, state := range states {
		if state.info.GetPCLwr() != "" {
			count++
		}
	}
	return count
}

func countConnectErrors(states []allPortsState) int {
	count := 0
	for _, state := range states {
		if state.connectErr != nil {
			count++
		}
	}
	return count
}
