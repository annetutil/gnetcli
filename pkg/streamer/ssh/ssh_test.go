package ssh

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/annetutil/gnetcli/pkg/streamer"
)

func TestSSHInterface(t *testing.T) {
	val := Streamer{}

	_, ok := interface{}(&val).(streamer.Connector)
	assert.True(t, ok, "not a Connector interface")
}
