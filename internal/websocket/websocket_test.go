package websocket

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsUpgrade(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		connection string
		upgrade    string
		want       bool
	}{
		{"canonical", http.MethodGet, "Upgrade", "websocket", true},
		{"case-insensitive tokens", http.MethodGet, "keep-alive, UPGRADE", "WebSocket", true},
		{"other protocol", http.MethodGet, "Upgrade", "h2c", false},
		{"no connection upgrade", http.MethodGet, "keep-alive", "websocket", false},
		{"not GET", http.MethodPost, "Upgrade", "websocket", false},
		{"plain request", http.MethodGet, "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/", nil)
			if tc.connection != "" {
				r.Header.Set("Connection", tc.connection)
			}
			if tc.upgrade != "" {
				r.Header.Set("Upgrade", tc.upgrade)
			}
			assert.Equal(t, tc.want, IsUpgrade(r))
		})
	}
}

func TestHub_ReserveEnforcesLimits(t *testing.T) {
	h := NewHub(nil)
	lim := Limits{MaxConnections: 3, MaxConnectionsPerClient: 2}

	a1, err := h.Reserve("/ws", "alice", lim)
	require.NoError(t, err)
	_, err = h.Reserve("/ws", "alice", lim)
	require.NoError(t, err)
	_, err = h.Reserve("/ws", "alice", lim)
	assert.ErrorIs(t, err, ErrClientFull)

	_, err = h.Reserve("/ws", "bob", lim)
	require.NoError(t, err)
	_, err = h.Reserve("/ws", "carol", lim)
	assert.ErrorIs(t, err, ErrRouteFull)

	// Limits are per route.
	_, err = h.Reserve("/other", "alice", lim)
	require.NoError(t, err)

	// Releasing (even twice) frees exactly one slot.
	a1.Release()
	a1.Release()
	_, err = h.Reserve("/ws", "carol", lim)
	require.NoError(t, err)
	_, err = h.Reserve("/ws", "dave", lim)
	assert.ErrorIs(t, err, ErrRouteFull)

	require.NoError(t, h.Shutdown(context.Background()))
	_, err = h.Reserve("/new", "erin", Limits{})
	assert.ErrorIs(t, err, ErrShuttingDown)
}

func TestFrameHeaderAndCopy(t *testing.T) {
	for _, size := range []int{0, 125, 126, 65535, 65536, 3*relayBufferSize + 7} {
		payload := bytes.Repeat([]byte{0xAB}, size)
		var frame bytes.Buffer
		frame.WriteByte(0x82) // FIN + binary
		switch {
		case size <= 125:
			frame.WriteByte(0x80 | byte(size))
		case size <= 0xFFFF:
			frame.Write([]byte{0x80 | 126, byte(size >> 8), byte(size)})
		default:
			frame.WriteByte(0x80 | 127)
			for i := 7; i >= 0; i-- {
				frame.WriteByte(byte(uint64(size) >> (8 * i)))
			}
		}
		frame.Write([]byte{1, 2, 3, 4}) // mask key
		frame.Write(payload)
		frame.WriteString("trailing bytes of the next frame")
		want := frame.Bytes()[:frame.Len()-len("trailing bytes of the next frame")]

		src := bufio.NewReader(bytes.NewReader(frame.Bytes()))
		buf := make([]byte, relayBufferSize)
		hlen, plen, err := readFrameHeader(src, buf)
		require.NoError(t, err)
		require.Equal(t, uint64(size), plen)

		var out bytes.Buffer
		readErr, writeErr := copyFrame(&out, src, buf, hlen, plen)
		require.NoError(t, readErr)
		require.NoError(t, writeErr)
		assert.Equal(t, want, out.Bytes(), "size %d: frame relayed byte-for-byte", size)

		rest, _ := src.Peek(8)
		assert.Equal(t, "trailing", string(rest), "size %d: nothing past the frame consumed", size)
	}
}

func TestCloseFrame(t *testing.T) {
	plain := closeFrame(1001, "going away", false)
	assert.Equal(t, []byte{0x88, 12, 0x03, 0xE9}, plain[:4])
	assert.Equal(t, "going away", string(plain[4:]))

	masked := closeFrame(1001, "going away", true)
	require.Len(t, masked, 2+4+12)
	assert.Equal(t, byte(0x80|12), masked[1])
	key := masked[2:6]
	payload := append([]byte(nil), masked[6:]...)
	for i := range payload {
		payload[i] ^= key[i%4]
	}
	assert.Equal(t, plain[2:], payload)

	long := closeFrame(1000, string(bytes.Repeat([]byte("x"), 300)), false)
	assert.LessOrEqual(t, int(long[1]), 125, "control frame payload capped at 125 bytes")
}
