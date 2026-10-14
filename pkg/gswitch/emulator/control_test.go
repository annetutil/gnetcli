package emulator_test

import (
	"encoding/json"
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestControlAPIAuthenticationAndStateChanges(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	const token = "local-test-token-123"
	h, err := d.ControlHandler(token)
	require.NoError(t, err)
	call := func(method, path, body, auth string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", auth)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	require.Equal(t, 401, call("GET", "/v1/state", "", "").Code)
	require.Equal(t, 200, call("GET", "/v1/state", "", "Bearer "+token).Code)
	before := d.Snapshot()
	for _, tc := range []struct{ path, body string }{
		{"/v1/reboot", "null"}, {"/v1/reboot", `{"unknown":true}`}, {"/v1/event-output", `{}`},
		{"/v1/events", `{"kind":"log","file":"secret"}`}, {"/v1/events", `{"kind":"log","route":"session"}`},
		{"/v1/lifecycle", `{"state":"bad\nstate"}`}, {"/v1/events", `{"kind":"log"}{}`},
		{"/v1/events", `{"kind":"log","text":"` + strings.Repeat("x", 70<<10) + `"}`},
	} {
		require.Equal(t, 400, call("POST", tc.path, tc.body, "Bearer "+token).Code, tc)
		require.Equal(t, before, d.Snapshot())
	}
	require.Equal(t, 200, call("POST", "/v1/lifecycle", `{"state":"degraded"}`, "Bearer "+token).Code)
	require.Equal(t, "degraded", d.Snapshot().Lifecycle)
	input(t, s, "sh")
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Route: "all", Policy: "defer", Text: "previously deferred"}))
	require.Equal(t, 200, call("POST", "/v1/event-output", `{"enabled":false}`, "Bearer "+token).Code)
	require.Equal(t, 200, call("POST", "/v1/events", `{"kind":"log","route":"all","text":"suppressed"}`, "Bearer "+token).Code)
	require.Empty(t, drain(s))
	result := input(t, s, "ow running\n")
	require.Contains(t, result, "initial")
	require.NotContains(t, result, "previously deferred")
	require.Equal(t, 200, call("POST", "/v1/event-output", `{"enabled":true}`, "Bearer "+token).Code)
	require.Equal(t, 200, call("POST", "/v1/events", `{"kind":"log","route":"all","policy":"raw","text":"visible"}`, "Bearer "+token).Code)
	require.Equal(t, "visible\r\n", drain(s))
	var trace []emulator.Trace
	out := call("GET", "/v1/trace", "", "Bearer "+token)
	require.NoError(t, json.Unmarshal(out.Body.Bytes(), &trace))
	require.NotEmpty(t, trace)
	require.NotContains(t, out.Body.String(), token)
	require.Equal(t, 200, call("POST", "/v1/reboot", `{}`, "Bearer "+token).Code)
	require.ErrorIs(t, s.Err(), emulator.ErrReboot)
	require.NoError(t, d.Close())
	require.Equal(t, 409, call("POST", "/v1/reboot", `{}`, "Bearer "+token).Code)
}

func TestControlAPISafety(t *testing.T) {
	d := device(t, emulator.Options{})
	_, err := d.ControlHandler("short")
	require.Error(t, err)
	h, err := d.ControlHandler("local-test-token-123")
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/v1/reboot", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer local-test-token-123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, 415, w.Code)
	req.Header.Set("Origin", "https://untrusted.example")
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	require.Equal(t, 403, w.Code)
}
