package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"

	"google.golang.org/grpc"
)

func TestIsExpectedShutdown(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "interrupt", err: Interrupted{Signal: os.Interrupt}, want: true},
		{name: "wrapped interrupt", err: fmt.Errorf("shutdown: %w", Interrupted{Signal: os.Interrupt}), want: true},
		{name: "grpc stopped", err: grpc.ErrServerStopped, want: true},
		{name: "http stopped", err: http.ErrServerClosed, want: true},
		{name: "unexpected", err: errors.New("listener failed"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpectedShutdown(tt.err); got != tt.want {
				t.Fatalf("isExpectedShutdown(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
