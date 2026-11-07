package emulator_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

const profileYAML = `
apiVersion: cli-emulator/v1
name: test
initialMode: exec
abbreviations: true
initialState: {hostname: sw, description: initial}
terminal: {logPolicy: redraw}
modes:
  exec: {prompt: "{{ .Running.hostname }}#"}
  config: {prompt: "{{ .Config.hostname }}(config)#"}
commands:
  - id: configure
    modes: [exec]
    syntax: configure terminal
    actions: [{op: push, mode: config}]
  - id: connect
    modes: [exec]
    syntax: connect
    actions: []
  - id: set
    modes: [config]
    syntax: "description <text:rest>"
    actions: [{op: set, path: [description], value: "{{ .Args.text }}"}]
  - id: exit
    modes: [config]
    syntax: exit
    actions: [{op: pop}]
  - id: show
    modes: [exec, config]
    syntax: show running
    actions: [{op: output, text: "{{ .Running.description }}\n"}]
  - id: slow
    modes: [exec]
    syntax: show slow
    actions:
      - {op: output, text: "Header\n"}
      - {op: checkpoint, name: header}
      - {op: output, after: 1s, text: "Body\n"}
  - id: begin
    modes: [exec]
    syntax: begin
    actions: [{op: begin}, {op: push, mode: config}]
  - id: commit
    modes: [config]
    syntax: commit
    actions: [{op: commit}]
  - id: abort
    modes: [config]
    syntax: abort
    actions: [{op: abort}, {op: pop}]
  - id: save
    modes: [exec]
    syntax: save
    actions: [{op: save}]
  - id: confirm
    modes: [exec]
    syntax: ask
    actions: [{op: dialog, dialog: confirmation}, {op: output, text: "done\n"}]
  - id: page
    modes: [exec]
    syntax: page
    actions: [{op: pager, value: 2}, {op: output, text: "one\ntwo\nthree\nfour\nfive\n"}]
  - id: monitor
    modes: [exec]
    syntax: monitor
    actions: [{op: monitor, value: true}]
  - id: line-echo
    modes: [exec]
    syntax: line-echo
    actions: [{op: echo, value: line}]
dialogs:
  confirmation:
    prompt: "Continue? [y/N]: "
    answers:
      - input: y
        actions: [{op: output, text: "accepted\n"}]
      - input: n
        actions: []
`

func load(t *testing.T, text string) *emulator.Profile {
	t.Helper()
	p, err := emulator.LoadProfile(strings.NewReader(text), nil)
	require.NoError(t, err)
	return p
}
func device(t *testing.T, options emulator.Options) *emulator.Device {
	t.Helper()
	options.Username = "test"
	options.Password = "secret"
	d, err := emulator.New(load(t, profileYAML), options)
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	return d
}
func drain(s *emulator.Session) string {
	var b strings.Builder
	for {
		select {
		case chunk, ok := <-s.Output():
			if !ok {
				return b.String()
			}
			b.Write(chunk)
		default:
			return b.String()
		}
	}
}
func attach(t *testing.T, d *emulator.Device) *emulator.Session {
	t.Helper()
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true, Username: "test"})
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })
	require.Equal(t, "sw#", drain(s))
	return s
}
func input(t *testing.T, s *emulator.Session, text string) string {
	t.Helper()
	require.NoError(t, s.Input([]byte(text)))
	return drain(s)
}

func TestProfileGrammarAndStrictValidation(t *testing.T) {
	p := load(t, profileYAML)
	m, err := p.Parse("exec", "conf t")
	require.NoError(t, err)
	require.Equal(t, "configure", m.Command)
	m, err = p.Parse("config", "desc text  with \"quotes\"")
	require.NoError(t, err)
	require.Equal(t, `text  with "quotes"`, m.Args["text"])
	for _, tc := range []struct{ line, kind string }{{"con", "ambiguous"}, {"configure", "incomplete"}, {"show nonexistent", "invalid"}, {"description x", "invalid"}} {
		_, err := p.Parse("exec", tc.line)
		var pe *emulator.ParseError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, tc.kind, pe.Kind)
	}
	require.Equal(t, []string{"running", "slow"}, p.Help("exec", "show "))
	for _, bad := range []string{
		profileYAML + "typo: true\n",
		strings.Replace(profileYAML, "initialMode: exec", "initialMode: absent", 1),
		strings.Replace(profileYAML, "op: save", "op: execute-shell", 1),
		strings.Replace(profileYAML, "<text:rest>", "<text:unknown>", 1),
		profileYAML + "---\nname: second\n",
	} {
		_, err := emulator.LoadProfile(strings.NewReader(bad), nil)
		require.Error(t, err)
	}
}

func TestSharedStateAndSessionIsolation(t *testing.T) {
	d := device(t, emulator.Options{})
	a, b := attach(t, d), attach(t, d)
	require.Contains(t, input(t, a, "conf t\r\ndescription new value\r\n"), "sw(config)#")
	require.Contains(t, input(t, b, "show running\n"), "new value\r\nsw#")
	require.NoError(t, a.Close())
	c := attach(t, d)
	require.Contains(t, input(t, c, "show running\n"), "new value")
	snapshot := d.Snapshot()
	snapshot.Running["description"] = "external mutation"
	require.Equal(t, "new value", d.Snapshot().Running["description"])
	other := device(t, emulator.Options{})
	require.Equal(t, "initial", other.Snapshot().Running["description"])
}

func TestCandidateCommitConflictAbortAndPersistence(t *testing.T) {
	d := device(t, emulator.Options{})
	a, b := attach(t, d), attach(t, d)
	input(t, a, "begin\ndescription pending\n")
	require.Equal(t, "initial", d.Snapshot().Running["description"])
	input(t, a, "commit\nexit\nsave\n")
	require.Equal(t, "pending", d.Snapshot().Startup["description"])
	input(t, b, "begin\ndescription b\n")
	input(t, a, "begin\ndescription a\ncommit\n")
	require.Contains(t, input(t, b, "commit\n"), "Candidate conflicts")
	input(t, b, "abort\n")
	require.Equal(t, "a", d.Snapshot().Running["description"])
	require.NoError(t, d.Reboot())
	require.ErrorIs(t, a.Err(), emulator.ErrReboot)
	require.Equal(t, "pending", d.Snapshot().Running["description"])
}

func TestBootLoginNoiseAndPersistentConsole(t *testing.T) {
	p := load(t, profileYAML+`
boot:
  - {at: 10ms, kind: raw, text: "BOOT\r\n", route: console}
  - {at: 20ms, kind: ready, text: "true"}
  - {at: 1s, kind: lifecycle, text: operational}
`)
	d, err := emulator.New(p, emulator.Options{Username: "test", Password: "secret"})
	require.NoError(t, err)
	defer d.Close()
	_, err = d.Attach(emulator.AttachOptions{Authenticated: true})
	require.ErrorIs(t, err, emulator.ErrNotReady)
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Empty(t, drain(s))
	require.NoError(t, d.Advance(20*time.Millisecond))
	require.Equal(t, "BOOT\r\nUsername: ", drain(s))
	require.Equal(t, "test\r\nPassword: ", input(t, s, "test\r\n"))
	require.Empty(t, input(t, s, "sec"))
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Source: "kernel", Route: "console", Text: "noise", Policy: "redraw"}))
	require.Equal(t, "\r\x1b[2Knoise\r\nPassword: ", drain(s))
	require.Equal(t, "\r\nsw#", input(t, s, "ret\n"))
	require.Equal(t, "booting", d.Snapshot().Lifecycle)
	input(t, s, "conf t\n")
	require.NoError(t, s.Close())
	s, err = d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Equal(t, "sw(config)#", drain(s))
	_, err = d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.ErrorIs(t, err, emulator.ErrConsoleBusy)
	require.NoError(t, d.Reboot())
	require.Empty(t, drain(s))
	require.NoError(t, d.Advance(20*time.Millisecond))
	require.Equal(t, "BOOT\r\nUsername: ", drain(s))
	require.NotContains(t, fmt.Sprint(d.Trace()), "secret")
}

func TestAsyncCommandCheckpointsAndCancellation(t *testing.T) {
	scenario, err := emulator.LoadScenario(strings.NewReader(`apiVersion: cli-emulator/v1
triggers:
  - on: checkpoint:header
    event: {kind: log, text: between, route: session, policy: raw}
  - on: authenticated
    after: 500ms
    event: {kind: log, text: after-login, route: session, policy: raw}
`), nil)
	require.NoError(t, err)
	d := device(t, emulator.Options{Scenario: scenario})
	s := attach(t, d)
	require.Equal(t, "show slow\r\nHeader\r\nbetween\r\n", input(t, s, "show slow\n"))
	require.NoError(t, d.Advance(500*time.Millisecond))
	require.Equal(t, "after-login\r\n", drain(s))
	require.NoError(t, d.Advance(500*time.Millisecond))
	require.Equal(t, "Body\r\nsw#", drain(s))
	input(t, s, "show slow\n")
	require.Equal(t, "^C\r\nsw#", input(t, s, "\x03"))
	require.NoError(t, d.Advance(time.Second))
	require.Empty(t, drain(s))
}

func TestDialogPagerEchoAndHelp(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	require.Equal(t, "ask\r\nContinue? [y/N]: ", input(t, s, "ask\r\n"))
	require.Contains(t, input(t, s, "wrong\n"), "Invalid answer")
	require.Equal(t, "y\r\naccepted\r\ndone\r\nsw#", input(t, s, "y\n"))
	require.Equal(t, "page\r\none\r\ntwo\r\n--More--", input(t, s, "page\n"))
	require.Equal(t, "\r\x1b[2Kthree\r\n--More--", input(t, s, "\r\n"))
	require.Equal(t, "\r\x1b[2Kfour\r\nfive\r\nsw#", input(t, s, " "))
	input(t, s, "show ")
	require.Equal(t, "\r\nrunning\r\nslow\r\nsw#show ", input(t, s, "?"))
	input(t, s, "\x03")
	input(t, s, "line-echo\n")
	require.Empty(t, input(t, s, "show run"))
	require.Equal(t, "show run\r\ninitial\r\nsw#", input(t, s, "\n"))
	// Cursor movement other than history navigation remains unsupported.
	require.Empty(t, input(t, s, "\x1b[D"))
}

func TestLogRoutingAndSlowConsumer(t *testing.T) {
	d := device(t, emulator.Options{OutputBuffer: 4})
	slow, fast := attach(t, d), attach(t, d)
	input(t, fast, "monitor\n")
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Route: "monitor", Text: "monitored"}))
	require.Empty(t, drain(slow))
	require.Contains(t, drain(fast), "monitored")
	for i := 0; i < 6; i++ {
		require.NoError(t, d.Inject(emulator.Event{Kind: "raw", Route: "all", Text: "x"}))
		require.Equal(t, "x", drain(fast))
	}
	require.ErrorIs(t, slow.Err(), emulator.ErrSlowConsumer)
	require.NoError(t, fast.Err())
	require.Contains(t, input(t, fast, "show running\n"), "initial")
}

func TestFragmentationAndConcurrentSessions(t *testing.T) {
	for _, fragment := range []int{1, 2, 7, 4096} {
		d := device(t, emulator.Options{})
		s := attach(t, d)
		text := "conf t\r\ndescription hello\r\nexit\r\nshow running\r\n"
		var out strings.Builder
		for len(text) > 0 {
			n := min(fragment, len(text))
			out.WriteString(input(t, s, text[:n]))
			text = text[n:]
		}
		require.Contains(t, out.String(), "hello\r\nsw#")
		require.NoError(t, s.Err())
	}
	d := device(t, emulator.Options{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		s := attach(t, d)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = s.Input([]byte("show running\n"))
				drain(s)
				d.Snapshot()
			}
		}()
	}
	wg.Wait()
}

func TestFixturesAndExamples(t *testing.T) {
	fsys := fstest.MapFS{"output.bin": {Data: []byte("\x00\x1b[31mraw\r")}}
	text := strings.Replace(profileYAML, `{op: output, text: "{{ .Running.description }}\n"}`, `{op: raw, file: output.bin}`, 1)
	p, err := emulator.LoadProfile(strings.NewReader(text), fsys)
	require.NoError(t, err)
	d, err := emulator.New(p, emulator.Options{})
	require.NoError(t, err)
	defer d.Close()
	s := attach(t, d)
	require.Contains(t, input(t, s, "show running\n"), "\x00\x1b[31mraw\r")
	_, err = emulator.LoadProfile(strings.NewReader(strings.Replace(text, "output.bin", "../output.bin", 1)), fsys)
	require.Error(t, err)
	for _, name := range []string{"iosxe.yaml", "huawei.yaml"} {
		root, err := os.OpenRoot("../../../examples/gswitch")
		require.NoError(t, err)
		f, err := root.Open(name)
		require.NoError(t, err)
		_, err = emulator.LoadProfile(f, root.FS())
		f.Close()
		root.Close()
		require.NoError(t, err)
	}
}

func TestStreamCancellationUnblocksWriter(t *testing.T) {
	d := device(t, emulator.Options{})
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Serve(ctx, server, emulator.AttachOptions{Authenticated: true, Username: "test"}) }()
	cancel()
	select {
	case err := <-done:
		require.True(t, err == nil || errors.Is(err, context.Canceled) || errors.Is(err, io.ErrClosedPipe))
	case <-time.After(time.Second):
		t.Fatal("Serve leaked blocked stream goroutines")
	}
}

func TestSlowStreamIsDisconnectedWithoutWaitingForClient(t *testing.T) {
	d := device(t, emulator.Options{OutputBuffer: 2})
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		done <- d.Serve(t.Context(), server, emulator.AttachOptions{Authenticated: true, Username: "test"})
	}()
	require.Eventually(t, func() bool { return len(d.Snapshot().Sessions) == 1 }, time.Second, time.Millisecond)
	for i := 0; i < 6; i++ {
		require.NoError(t, d.Inject(emulator.Event{Kind: "raw", Route: "all", Text: "data"}))
	}
	select {
	case err := <-done:
		require.ErrorIs(t, err, emulator.ErrSlowConsumer)
	case <-time.After(time.Second):
		t.Fatal("slow stream blocked device shutdown")
	}
}

func TestDeferredLogAndLongInput(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	input(t, s, "show ")
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Route: "all", Text: "deferred", Policy: "defer"}))
	require.Empty(t, drain(s))
	require.Contains(t, input(t, s, "running\n"), "initial\r\ndeferred\r\nsw#")
	input(t, s, "configure terminal\n")
	long := strings.Repeat("x", 1000)
	input(t, s, "description "+long+"\n")
	require.NoError(t, s.Err())
	require.Equal(t, long, d.Snapshot().Running["description"])
}

func TestScenarioValidationAndStableEventOrder(t *testing.T) {
	_, err := emulator.LoadScenario(strings.NewReader("apiVersion: cli-emulator/v1\ntimeline:\n  - {at: -1s, kind: log, text: bad}\n"), nil)
	require.Error(t, err)
	scenario := &emulator.Scenario{APIVersion: "cli-emulator/v1", Triggers: []emulator.Trigger{{On: "command:absent", Event: emulator.Event{Kind: "log"}}}}
	_, err = emulator.New(load(t, profileYAML), emulator.Options{Scenario: scenario})
	require.Error(t, err)
	var transcripts []string
	for i := 0; i < 3; i++ {
		s, err := emulator.LoadScenario(strings.NewReader(`apiVersion: cli-emulator/v1
timeline:
  - {at: 1s, kind: raw, text: first, route: all}
  - {at: 1s, kind: raw, text: second, route: all}
 `), nil)
		require.NoError(t, err)
		d := device(t, emulator.Options{Scenario: s})
		session := attach(t, d)
		require.NoError(t, d.Advance(time.Second))
		transcripts = append(transcripts, drain(session))
	}
	require.Equal(t, []string{"firstsecond", "firstsecond", "firstsecond"}, transcripts)
}

func FuzzInputFragmentation(f *testing.F) {
	f.Add([]byte("show running\r\n"))
	f.Add([]byte("\x1b[Ashow slow\n\x03"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		p, err := emulator.LoadProfile(strings.NewReader(profileYAML), nil)
		require.NoError(t, err)
		var outputs []string
		for _, size := range []int{1, 7, 4096} {
			d, err := emulator.New(p, emulator.Options{})
			require.NoError(t, err)
			s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
			require.NoError(t, err)
			var output strings.Builder
			output.WriteString(drain(s))
			for i := 0; i < len(data); i += size {
				_ = s.Input(data[i:min(i+size, len(data))])
				output.WriteString(drain(s))
			}
			require.NoError(t, d.Advance(2*time.Second))
			output.WriteString(drain(s))
			outputs = append(outputs, output.String())
			d.Close()
		}
		require.Equal(t, outputs[0], outputs[1])
		require.Equal(t, outputs[0], outputs[2])
	})
}
