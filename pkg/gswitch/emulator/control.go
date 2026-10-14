package emulator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"
)

// ControlHandler exposes a test-only API. Tokens are never recorded in trace.
// The caller must serve it on loopback; ServeControl enforces that restriction.
func (d *Device) ControlHandler(token string) (http.Handler, error) {
	if len(token) < 16 || strings.ContainsAny(token, "\r\n \t") {
		return nil, fmt.Errorf("control token needs at least 16 characters and no whitespace")
	}
	digest := sha256.Sum256([]byte("Bearer " + token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(got[:], digest[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Origin") != "" {
			http.Error(w, "browser origins are not supported", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		fail := func(code int, err error) {
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		}
		if r.Method == http.MethodGet {
			switch r.URL.Path {
			case "/v1/state":
				_ = json.NewEncoder(w).Encode(d.Snapshot())
			case "/v1/trace":
				_ = json.NewEncoder(w).Encode(d.Trace())
			default:
				fail(404, fmt.Errorf("unknown endpoint"))
			}
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			fail(405, fmt.Errorf("unsupported method"))
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			fail(415, fmt.Errorf("Content-Type must be application/json"))
			return
		}
		decode := func(value any) error {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
			if err != nil {
				return err
			}
			body = bytes.TrimSpace(body)
			if len(body) == 0 || body[0] != '{' {
				return fmt.Errorf("body must be a JSON object")
			}
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(value); err != nil {
				return err
			}
			var extra any
			if err := dec.Decode(&extra); err != io.EOF {
				return fmt.Errorf("body must contain one JSON object")
			}
			return nil
		}
		switch r.URL.Path {
		case "/v1/events":
			var event Event
			if err = decode(&event); err == nil {
				err = d.Inject(event)
			}
		case "/v1/lifecycle":
			var body struct {
				State string `json:"state"`
			}
			if err = decode(&body); err == nil {
				if body.State == "" || len(body.State) > 128 || strings.ContainsAny(body.State, "\r\n\t ") {
					err = fmt.Errorf("invalid lifecycle state")
				} else {
					err = d.Inject(Event{Kind: "lifecycle", Text: body.State})
				}
			}
		case "/v1/event-output":
			var body struct {
				Enabled *bool `json:"enabled"`
			}
			if err = decode(&body); err == nil {
				if body.Enabled == nil {
					err = fmt.Errorf("enabled is required")
				} else {
					err = d.SetEventOutput(*body.Enabled)
				}
			}
		case "/v1/reboot":
			var body struct{}
			if err = decode(&body); err == nil {
				err = d.Reboot()
			}
		default:
			fail(404, fmt.Errorf("unknown endpoint"))
			return
		}
		if err != nil {
			code := 400
			if errors.Is(err, ErrClosed) {
				code = 409
			}
			fail(code, err)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}), nil
}

// ServeControl serves only on a TCP loopback listener, disabled unless explicitly enabled.
func (d *Device) ServeControl(ctx context.Context, listener net.Listener, token string) error {
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !addr.IP.IsLoopback() {
		return fmt.Errorf("control API requires a TCP loopback listener")
	}
	handler, err := d.ControlHandler(token)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err = server.Serve(listener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
