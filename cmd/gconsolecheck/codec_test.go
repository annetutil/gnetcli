package main

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/stretchr/testify/require"
)

func TestEncodeConserverData(t *testing.T) {
	input := []byte{0x00, 0x05, 'c', 0xff, 0x7f}
	want := []byte{0x00, 0x05, 'c', '\\', '0', '0', '5', 'c', 0xff, 0xff, 0x7f}

	require.Equal(t, want, encodeConserverData(input))
}

func TestConserverDecoderHandlesSplitCommandByte(t *testing.T) {
	decoder := conserverDecoder{}

	first, err := decoder.Decode([]byte{'a', 0xff})
	require.NoError(t, err)
	require.Equal(t, []byte{'a'}, first)
	require.True(t, decoder.pendingCommand)

	second, err := decoder.Decode([]byte{0xff, 'b'})
	require.NoError(t, err)
	require.Equal(t, []byte{0xff, 'b'}, second)
	require.False(t, decoder.pendingCommand)
}

func TestConserverDecoderRejectsControlCommand(t *testing.T) {
	decoder := conserverDecoder{}

	_, err := decoder.Decode([]byte{0xff, 'Z'})

	require.ErrorContains(t, err, "unexpected conserver command")
}

func TestFilterQuoteResponsesHandlesSplitAcknowledgements(t *testing.T) {
	session := &conserverDataSession{}
	session.expectedQuotes.Store(2)

	first := session.filterQuoteResponses([]byte("payload[quo"))
	second := session.filterQuoteResponses([]byte("te \\005]more[quote \\005]tail"))

	require.Equal(t, []byte("payload"), first)
	require.Equal(t, []byte("moretail"), second)
	require.Zero(t, session.expectedQuotes.Load())
	require.Empty(t, session.quoteBuffer)
}

func TestFilterQuoteResponsesDoesNotChangeDataWithoutExpectedAcknowledgement(t *testing.T) {
	session := &conserverDataSession{}
	data := []byte("payload[quote \\005]tail")

	require.Equal(t, data, session.filterQuoteResponses(data))
}

func TestDecodeReadErrorReturnsPartialData(t *testing.T) {
	session := &conserverDataSession{}
	readErr := streamer.ThrowReadTimeoutException([]byte("partial"))

	data, err := session.decodeReadError(readErr, 10)

	require.NoError(t, err)
	require.Equal(t, []byte("partial"), data)
}
