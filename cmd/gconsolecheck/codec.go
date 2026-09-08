package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/streamer/console"
)

const (
	conserverAttention = byte(0x05)
	conserverCommand   = byte(0xff)
)

var quoteAttentionResponse = []byte("[quote \\005]")

type dataSession interface {
	WriteData(context.Context, []byte) error
	ReadData(context.Context, int) ([]byte, error)
	ReadAvailable(context.Context, time.Duration) ([]byte, error)
	Close()
}

type conserverDataSession struct {
	stream         *console.Streamer
	cancel         context.CancelFunc
	decoder        conserverDecoder
	decodedExtra   []byte
	quoteBuffer    []byte
	expectedQuotes atomic.Int64
}

func newConserverDataSession(stream *console.Streamer, cancel context.CancelFunc) *conserverDataSession {
	return &conserverDataSession{stream: stream, cancel: cancel}
}

func encodeConserverData(data []byte) []byte {
	encoded := make([]byte, 0, len(data))
	for _, value := range data {
		switch value {
		case conserverAttention:
			encoded = append(encoded, conserverAttention, 'c', '\\', '0', '0', '5')
		case conserverCommand:
			encoded = append(encoded, conserverCommand, conserverCommand)
		default:
			encoded = append(encoded, value)
		}
	}
	return encoded
}

type conserverDecoder struct {
	pendingCommand bool
}

func (d *conserverDecoder) Decode(data []byte) ([]byte, error) {
	decoded := make([]byte, 0, len(data))
	for _, value := range data {
		if d.pendingCommand {
			d.pendingCommand = false
			if value != conserverCommand {
				return nil, fmt.Errorf("unexpected conserver command 0xff 0x%02x", value)
			}
			decoded = append(decoded, conserverCommand)
			continue
		}
		if value == conserverCommand {
			d.pendingCommand = true
			continue
		}
		decoded = append(decoded, value)
	}
	return decoded, nil
}

func (s *conserverDataSession) WriteData(ctx context.Context, data []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.expectedQuotes.Add(int64(bytes.Count(data, []byte{conserverAttention})))
	return s.stream.Write(encodeConserverData(data))
}

func (s *conserverDataSession) ReadData(ctx context.Context, size int) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("negative read size %d", size)
	}
	result := make([]byte, 0, size)
	if len(s.decodedExtra) > 0 {
		use := min(size, len(s.decodedExtra))
		result = append(result, s.decodedExtra[:use]...)
		s.decodedExtra = s.decodedExtra[use:]
	}
	for len(result) < size {
		remaining := size - len(result)
		readData, err := s.stream.ReadSome(ctx, remaining)
		if err != nil {
			partial, decodeErr := s.decodeReadError(err, remaining)
			if decodeErr != nil {
				return result, errors.Join(err, decodeErr)
			}
			result = append(result, partial...)
			return result, err
		}
		decoded, err := s.decodeIncoming(readData)
		if err != nil {
			return nil, err
		}
		if len(decoded) == 0 {
			continue
		}
		use := min(remaining, len(decoded))
		result = append(result, decoded[:use]...)
		s.decodedExtra = append(s.decodedExtra, decoded[use:]...)
	}
	return result, nil
}

func (s *conserverDataSession) decodeReadError(err error, remaining int) ([]byte, error) {
	var timeoutErr *streamer.ReadTimeoutException
	if !errors.As(err, &timeoutErr) || len(timeoutErr.LastRead) == 0 {
		return nil, nil
	}
	decoded, decodeErr := s.decodeIncoming(timeoutErr.LastRead)
	if decodeErr != nil {
		return nil, decodeErr
	}
	use := min(remaining, len(decoded))
	s.decodedExtra = append(s.decodedExtra, decoded[use:]...)
	return decoded[:use], nil
}

func (s *conserverDataSession) ReadAvailable(ctx context.Context, duration time.Duration) ([]byte, error) {
	result := append([]byte(nil), s.decodedExtra...)
	s.decodedExtra = nil
	readRes, err := s.stream.XRead(ctx, defaultChunkSize, duration, nil)
	if err != nil {
		return nil, err
	}
	if readRes.RetType == streamer.EOF {
		return nil, io.EOF
	}
	decoded, err := s.decodeIncoming(readRes.BytesRes)
	if err != nil {
		return nil, err
	}
	result = append(result, decoded...)
	if pending := s.expectedQuotes.Load(); pending != 0 {
		return nil, fmt.Errorf("did not receive %d conserver quote acknowledgements", pending)
	}
	if s.decoder.pendingCommand {
		return nil, errors.New("incomplete conserver command at end of quiet window")
	}
	return result, nil
}

func (s *conserverDataSession) decodeIncoming(data []byte) ([]byte, error) {
	return s.decoder.Decode(s.filterQuoteResponses(data))
}

func (s *conserverDataSession) filterQuoteResponses(data []byte) []byte {
	if s.expectedQuotes.Load() == 0 && len(s.quoteBuffer) == 0 {
		return data
	}
	s.quoteBuffer = append(s.quoteBuffer, data...)
	result := make([]byte, 0, len(s.quoteBuffer))
	for s.expectedQuotes.Load() > 0 {
		if index := bytes.Index(s.quoteBuffer, quoteAttentionResponse); index >= 0 {
			result = append(result, s.quoteBuffer[:index]...)
			s.quoteBuffer = s.quoteBuffer[index+len(quoteAttentionResponse):]
			s.expectedQuotes.Add(-1)
			continue
		}
		keep := quotePrefixSuffixLen(s.quoteBuffer)
		result = append(result, s.quoteBuffer[:len(s.quoteBuffer)-keep]...)
		s.quoteBuffer = s.quoteBuffer[len(s.quoteBuffer)-keep:]
		return result
	}
	result = append(result, s.quoteBuffer...)
	s.quoteBuffer = nil
	return result
}

func quotePrefixSuffixLen(data []byte) int {
	limit := min(len(data), len(quoteAttentionResponse)-1)
	for size := limit; size > 0; size-- {
		if bytes.Equal(data[len(data)-size:], quoteAttentionResponse[:size]) {
			return size
		}
	}
	return 0
}

func (s *conserverDataSession) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	s.stream.Close()
}
