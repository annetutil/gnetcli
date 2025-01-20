package console

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseInfoLine(t *testing.T) {
	line := "ttyS16:consoles-dc.domain,147,10102:/:/dev/ttyMI23,9600n,4::up:rw:,log,noact,nobrk,notask,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:"
	res, err := parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS16")
	require.Equal(t, res.port, 10102)
	// locked
	line = "ttyS11:consoles-dc.domain,147,10102:/:/dev/ttyMI18,9600n,9:w@login@dc1-srv.net@22:up:rw:,log,noact,nobrk,notask,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:\n"
	res, err = parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS11")
	require.Equal(t, res.port, 10102)
	// old console ?
	line = "ttyS32:consoles-dc1.domains,12833,10102:/:/dev/ttyS32,9600n,4::up:rw:,log,noact,nobrk,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:"
	res, err = parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS32")
	require.Equal(t, res.port, 10102)
	line = "ttyS11:consoles-1.domain,151,10102:/:/dev/ttyMI18,9600n,-1::down:rw:,log,noact,nobrk,notask,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:"
	res, err = parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS11")
	require.Equal(t, res.iostate, "down")
	require.Equal(t, res.port, 10102)
	line = "ttyS23:consoles-1.yndx.net,194,10103:/:/dev/ttyMI14,9600n,13:w@login@::ffff:10.0.0.1@1:up:rw:,log,noact,nobrk,notask,0,-1:1:noautoup::reinitoncc,autoreinit,login::0:\n"
	res, err = parseInfoLine([]byte(line))
	require.NoError(t, err)
	require.Equal(t, res.portName, "ttyS23")
	require.Equal(t, res.iostate, "up")
	require.Equal(t, res.port, 10103)
}
