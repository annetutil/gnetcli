package streamer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/annetutil/gnetcli/pkg/expr"
)

func TestGenericReadNSimple(t *testing.T) {
	data := []byte("testt")
	ch := setupChan([]byte("testt"))
	ctx := context.Background()
	buffer := []byte{}
	readSize := 2
	readTimeout := 2 * time.Second
	res, extra, read, err := GenericReadX(ctx, buffer, ch, readSize, readTimeout, nil, 5, 0)

	left := readAll(ch)
	assert.NoError(t, err)
	assert.Equal(t, data, res.BytesRes)
	assert.Empty(t, extra)
	assert.Empty(t, left)
	assert.Equal(t, []byte("testt"), read)
}

func TestGenericReadNBuff(t *testing.T) {
	ch := make(chan []byte, 10)
	ctx := context.Background()
	buffer := []byte("1")
	data := []byte("test")
	for i := 0; i < len(data); i++ {
		ch <- []byte{data[i]}
	}
	res, extra, read, err := GenericReadX(ctx, buffer, ch, 1, 2*time.Second, nil, 3, 0)

	left := readAll(ch)
	assert.NoError(t, err)
	assert.Equal(t, []byte("1te"), res.BytesRes)
	assert.Equal(t, []byte("st"), extra)
	assert.Equal(t, []byte{}, left)
	assert.Equal(t, []byte("test"), read)
}

func readAll(ch chan []byte) []byte {
	close(ch)
	left := []byte{}
	for {
		v, ok := <-ch
		if !ok {
			break
		}
		left = append(left, v...)
	}
	return left
}

func TestGenericReadToSimple(t *testing.T) {
	ctx := context.Background()
	buffer := []byte(nil)
	readSize := 2
	readTimeout := 2 * time.Second
	ch := setupChan([]byte("aest"))
	pat := expr.NewSimpleExpr().FromPattern("es")
	res, extra, read, err := GenericReadX(ctx, buffer, ch, readSize, readTimeout, pat, 0, 0)

	left := readAll(ch)
	assert.NoError(t, err)
	assert.Equal(t, NewReadXRes(Expr, []byte("aest"), NewReadResImpl([]byte("a"), []byte("t"), map[string][]byte{}, []byte("es"), 0), []byte("t")), res)
	assert.Equal(t, []byte("t"), extra)
	assert.Equal(t, []byte(""), left)
	assert.Equal(t, []byte("aest"), read)
}

func setupChan(data []byte) chan []byte {
	ch := make(chan []byte, len(data))
	for i := 0; i < len(data); i++ {
		ch <- []byte{data[i]}
	}
	return ch
}

func TestGenericReadXCtxDoneFlushChannel(t *testing.T) {
	ch := make(chan []byte, 1)
	ch <- []byte("pending in channel")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	pat := expr.NewSimpleExpr().FromPattern("never-matches")
	_, _, _, err := GenericReadX(ctx, nil, ch, 4096, time.Second, pat, 0, 0)
	require.Error(t, err)

	require.ErrorIs(t, err, context.Canceled)
	var rt *ReadTimeoutException
	require.True(t, errors.As(err, &rt))
	require.Equal(t, "pending in channel", string(rt.LastRead))
	require.ErrorIs(t, rt.Cause, context.Canceled)
	require.Equal(t, `read timeout error caused by context canceled. last seen: "pending in channel"`, err.Error())
	require.Empty(t, ch, "channel should be drained")
}

func TestGenericReadXTimeoutNoExtraLeak(t *testing.T) {
	// Regression: on Timeout, extra must be empty so the next XRead call does not
	// replay the same buffered data, which would produce duplicate console output.
	ch := make(chan []byte, 1)
	ch <- []byte("hello")
	ctx := context.Background()
	pat := expr.NewSimpleExpr().FromPattern("never-matches")
	// readTimeout > maxDuration so that maxDurationTimeout fires first (Timeout path).
	res, extra, _, err := GenericReadX(ctx, nil, ch, 4096, time.Second, pat, 0, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, Timeout, res.RetType)
	assert.Equal(t, []byte("hello"), res.BytesRes)
	assert.Empty(t, extra, "extra must be empty after timeout to prevent replaying data on next read")
}

func TestGenericSplitBytes(t *testing.T) {
	a, b := splitBytes([]byte("1234"), 2)
	assert.Equal(t, []byte("12"), a)
	assert.Equal(t, []byte("34"), b)
	a, b = splitBytes([]byte("1234"), 0)
	assert.Equal(t, []byte{}, a)
	assert.Equal(t, []byte("1234"), b)
	a, b = splitBytes([]byte(""), 0)
	assert.Equal(t, []byte{}, a)
	assert.Equal(t, []byte{}, b)
	a, b = splitBytes([]byte("1234"), 5)
	assert.Equal(t, []byte("1234"), a)
	assert.Equal(t, []byte{}, b)
}
