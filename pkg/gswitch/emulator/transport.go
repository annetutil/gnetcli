package emulator

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

// Serve attaches a byte-stream transport. Exactly one goroutine writes stream.
// Closing stream must unblock both Read and Write, as net.Conn/ssh.Channel do.
func (d *Device) Serve(ctx context.Context, stream io.ReadWriteCloser, options AttachOptions) error {
	defer stream.Close()
	s, err := d.Attach(options)
	if err != nil {
		return err
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { stream.Close(); s.Close() })
	defer stop()
	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if e := s.Input(buf[:n]); e != nil {
					readDone <- e
					return
				}
			}
			if err != nil {
				readDone <- err
				return
			}
		}
	}()
	writeDone := make(chan error, 1)
	go func() { _, err := io.Copy(stream, s); writeDone <- err }()
	var result error
	sessionDone := s.Done()
	readSeen, writeSeen := false, false
waiting:
	for {
		select {
		case result = <-readDone:
			readSeen = true
			break waiting
		case result = <-writeDone:
			writeSeen = true
			break waiting
		case <-sessionDone:
			if s.Err() != nil {
				result = s.Err()
				break waiting
			}
			// A normal logout drains queued output; fatal errors close blocked I/O.
			sessionDone = nil
		case <-ctx.Done():
			result = ctx.Err()
			break waiting
		}
	}
	stream.Close()
	s.Close()
	if !readSeen {
		<-readDone
	}
	if !writeSeen {
		<-writeDone
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.Err() != nil {
		return s.Err()
	}

	if errors.Is(result, io.EOF) {
		return nil
	}
	return result
}

// ServeConsole exposes one persistent console over raw TCP, not Telnet/RFC2217.
// Only one attachment can own this line at a time. No old output is replayed.
func (d *Device) ServeConsole(ctx context.Context, listener net.Listener, name string) error {
	if name == "" {
		name = "console0"
	}
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() { cancel(); listener.Close(); wg.Wait() }()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = d.Serve(ctx, conn, AttachOptions{Console: name}) }()
	}
}
