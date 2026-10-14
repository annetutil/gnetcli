package main

import (
	"context"
	"io"
	"sync"

	"github.com/annetutil/gnetcli/pkg/gswitch"
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
)

func fallback(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func serveEmulatedSSH(ctx context.Context, d *emulator.Device, stream io.ReadWriteCloser, info gswitch.SSHSession, console bool) error {
	options := emulator.AttachOptions{Authenticated: true, Username: info.Username, Columns: info.Size.Columns, Rows: info.Size.Rows}
	if console {
		options.Console = "console0"
	}
	s, err := d.Attach(options)
	if err != nil {
		if console {
			_, _ = io.WriteString(stream, "Console unavailable: "+err.Error()+"\r\n")
		}
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case size, ok := <-info.Resizes:
				if !ok {
					return
				}
				if s.Resize(size.Columns, size.Rows) != nil {
					return
				}
			}
		}
	}()
	return s.Serve(ctx, stream)
}
