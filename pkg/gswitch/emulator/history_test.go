package emulator_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

const historyUp = "\x1b[A"
const historyDown = "\x1b[B"

func historyRedraw(line string) string { return "\r\x1b[2Ksw#" + line }

func TestHistoryNavigationRestoresDraftWithoutExecution(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	input(t, s, "show running\nconnect\nsh")
	before, trace := d.Snapshot(), d.Trace()
	require.Equal(t, historyRedraw("connect"), input(t, s, historyUp))
	require.Equal(t, historyRedraw("show running"), input(t, s, historyUp))
	require.Equal(t, "\a", input(t, s, historyUp))
	require.Equal(t, historyRedraw("connect"), input(t, s, historyDown))
	require.Equal(t, historyRedraw("sh"), input(t, s, historyDown))
	require.Equal(t, "\a", input(t, s, historyDown))
	require.Equal(t, before, d.Snapshot())
	require.Equal(t, trace, d.Trace())
	require.Equal(t, "ow ", input(t, s, "\t"))
	require.Contains(t, input(t, s, "ru\t\n"), "initial\r\nsw#")
}

func TestHistoryEditingDoesNotChangeSavedEntries(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	input(t, s, "configure terminal\ndescription original\n")
	require.Equal(t, "\r\x1b[2Ksw(config)#description original", input(t, s, historyUp))
	input(t, s, " temporary")
	require.Equal(t, "\r\x1b[2Ksw(config)#configure terminal", input(t, s, historyUp))
	require.Equal(t, "\r\x1b[2Ksw(config)#description original", input(t, s, historyDown))
	input(t, s, " updated\n")
	require.Equal(t, "original updated", d.Snapshot().Running["description"])
	require.Equal(t, "\r\x1b[2Ksw(config)#description original updated", input(t, s, historyUp))
	// Remove the suffix using the existing editor, then submit the recalled line.
	input(t, s, strings.Repeat("\x7f", len(" updated"))+"\n")
	require.Equal(t, "original", d.Snapshot().Running["description"])
	require.Equal(t, "\r\x1b[2Ksw(config)#description original", input(t, s, historyUp))
	require.Equal(t, "\r\x1b[2Ksw(config)#description original updated", input(t, s, historyUp))
}

func TestHistoryCapacityAndEntryPolicy(t *testing.T) {
	p := load(t, strings.Replace(profileYAML, "terminal: {logPolicy: redraw}", "terminal: {logPolicy: redraw, historySize: 2}", 1))
	d := validationDevice(t, p)
	s := attach(t, d)
	input(t, s, "show running\nconnect\nbad command\n\n   \n")
	require.Equal(t, historyRedraw("bad command"), input(t, s, historyUp))
	require.Equal(t, historyRedraw("connect"), input(t, s, historyUp))
	require.Equal(t, "\a", input(t, s, historyUp))
	input(t, s, "\x03connect\nconnect\n")
	// Repeated submissions retain their order; arrow navigation itself is not an entry.
	require.Equal(t, historyRedraw("connect"), input(t, s, historyUp))
	require.Equal(t, historyRedraw("connect"), input(t, s, historyUp))
	require.Equal(t, "\a", input(t, s, historyUp))
	for _, size := range []int{-1, 1001} {
		_, err := emulator.LoadProfile(strings.NewReader(strings.Replace(profileYAML, "terminal: {logPolicy: redraw}", fmt.Sprintf("terminal: {historySize: %d}", size), 1)), nil)
		require.ErrorContains(t, err, "historySize")
	}
	disabled := validationDevice(t, load(t, strings.Replace(profileYAML, "terminal: {logPolicy: redraw}", "terminal: {historySize: 0}", 1)))
	noHistory := attach(t, disabled)
	input(t, noHistory, "show running\n")
	require.Equal(t, "\a", input(t, noHistory, historyUp))
	defaultDevice := device(t, emulator.Options{})
	defaultSession := attach(t, defaultDevice)
	for i := 0; i < 101; i++ {
		input(t, defaultSession, fmt.Sprintf("unknown-%d\n", i))
	}
	for i := 100; i >= 1; i-- {
		require.Equal(t, historyRedraw(fmt.Sprintf("unknown-%d", i)), input(t, defaultSession, historyUp))
	}
	require.Equal(t, "\a", input(t, defaultSession, historyUp))
}

func TestHistorySessionIsolation(t *testing.T) {
	d := device(t, emulator.Options{})
	a, b := attach(t, d), attach(t, d)
	input(t, a, "show running\n")
	require.Equal(t, "\a", input(t, b, historyUp))
	input(t, b, "connect\n")
	require.Equal(t, historyRedraw("show running"), input(t, a, historyUp))
	require.Equal(t, historyRedraw("connect"), input(t, b, historyUp))
	require.NoError(t, a.Close())
	next := attach(t, d)
	require.Equal(t, "\a", input(t, next, historyUp))
}

func TestHistoryExcludesAuthenticationAndDialogAnswers(t *testing.T) {
	text := strings.Replace(profileYAML, "  confirmation:\n", "  confirmation:\n    secret: true\n", 1)
	d, err := emulator.New(load(t, text), emulator.Options{Username: "test", Password: "secret"})
	require.NoError(t, err)
	defer d.Close()
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	drain(s)
	require.Empty(t, input(t, s, historyUp))
	input(t, s, "test\n")
	require.Empty(t, input(t, s, "sec"+historyUp+"ret"+historyDown))
	require.Equal(t, "\r\nsw#", input(t, s, "\n"))
	require.Equal(t, "\a", input(t, s, historyUp))
	input(t, s, "connect\nask\n")
	require.Empty(t, input(t, s, historyUp+historyDown))
	require.Contains(t, input(t, s, "secret-answer\n"), "Invalid answer")
	require.Equal(t, "\r\naccepted\r\ndone\r\nsw#", input(t, s, "y\n"))
	require.Equal(t, historyRedraw("ask"), input(t, s, historyUp))
	require.Equal(t, historyRedraw("connect"), input(t, s, historyUp))
	require.Equal(t, "\a", input(t, s, historyUp))
	require.NotContains(t, fmt.Sprint(d.Trace()), "secret")
}

func TestHistoryConsoleReconnectLogoutAndReboot(t *testing.T) {
	d := device(t, emulator.Options{})
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	drain(s)
	input(t, s, "test\nsecret\nconnect\n")
	require.NoError(t, s.Close())
	s, err = d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Equal(t, "sw#", drain(s))
	require.Equal(t, historyRedraw("connect"), input(t, s, historyUp))
	input(t, s, "\x03\x04")
	input(t, s, "test\nsecret\n")
	require.Equal(t, "\a", input(t, s, historyUp))
	input(t, s, "show running\n")
	require.NoError(t, d.Reboot())
	require.Equal(t, "Username: ", drain(s))
	input(t, s, "test\nsecret\n")
	require.Equal(t, "\a", input(t, s, historyUp))
}

func TestHistoryInteractionGuardsAndCancel(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	input(t, s, "page\n")
	require.Empty(t, input(t, s, historyUp+historyDown))
	require.Equal(t, "paging", d.Snapshot().Sessions[0].Interaction)
	input(t, s, "q")
	require.Equal(t, historyRedraw("page"), input(t, s, historyUp))
	input(t, s, "\x03show slow\n")
	require.Empty(t, input(t, s, historyUp+historyDown))
	require.Equal(t, "executing", d.Snapshot().Sessions[0].Interaction)
	require.Equal(t, "^C\r\nsw#", input(t, s, "\x03"))
	require.NoError(t, d.Advance(time.Second))
	require.Empty(t, drain(s))
	require.Equal(t, historyRedraw("show slow"), input(t, s, historyUp))
	input(t, s, historyDown+"cancelled draft"+historyUp)
	require.Equal(t, "^C\r\nsw#", input(t, s, "\x03"))
	require.Equal(t, "\a", input(t, s, historyDown))
	require.Equal(t, historyRedraw("show slow"), input(t, s, historyUp))
	require.Equal(t, historyRedraw(""), input(t, s, historyDown))
}

func TestHistoryEscapeSequencesAndRedraw(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	input(t, s, "show running\nconnect\ndraft")
	require.Empty(t, input(t, s, "\x1b"))
	require.Empty(t, input(t, s, "["))
	require.Equal(t, historyRedraw("connect"), input(t, s, "A"))
	require.Equal(t, historyRedraw("show running"), input(t, s, "\x1bOA"))
	require.Equal(t, historyRedraw("connect"), input(t, s, "\x1bOB"))
	require.Equal(t, historyRedraw("show running"), input(t, s, "\x1b[1A"))
	require.Empty(t, input(t, s, "\x1b[1;5B\x1b[D\x1b["+strings.Repeat("1", 100)+"A"))
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Route: "all", Text: "noise", Policy: "redraw"}))
	require.Equal(t, "\r\x1b[2Knoise\r\nsw#show running", drain(s))
	require.Equal(t, historyRedraw("connect"), input(t, s, historyDown))
	require.Equal(t, historyRedraw("draft"), input(t, s, historyDown))
	require.Equal(t, "^C\r\nsw#", input(t, s, "\x1b[\x03"))
}

func TestHistoryEchoModesAndFragmentedInput(t *testing.T) {
	for _, echo := range []string{"line", "none"} {
		p := load(t, strings.Replace(profileYAML, "terminal: {logPolicy: redraw}", "terminal: {echo: "+echo+"}", 1))
		d := validationDevice(t, p)
		s := attach(t, d)
		input(t, s, "show running\n")
		require.Empty(t, input(t, s, historyUp))
		output := input(t, s, "\n")
		if echo == "line" {
			require.Equal(t, "show running\r\ninitial\r\nsw#", output)
		} else {
			require.Equal(t, "\r\ninitial\r\nsw#", output)
		}
	}
	var outputs []string
	text := "show running\nconnect\nsh" + historyUp + "\x1bOA\x1bOB" + historyDown + "\tru\t\r\n"
	for _, size := range []int{1, 2, 7, 4096} {
		d := device(t, emulator.Options{})
		s := attach(t, d)
		var output strings.Builder
		for i := 0; i < len(text); i += size {
			output.WriteString(input(t, s, text[i:min(i+size, len(text))]))
		}
		outputs = append(outputs, output.String())
	}
	for _, output := range outputs[1:] {
		require.Equal(t, outputs[0], output)
	}
}
