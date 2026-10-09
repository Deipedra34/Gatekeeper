package websocket

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Close reasons, used as the "reason" label of metrics.WebSocketClosed.
const (
	CloseReasonClient      = "client"
	CloseReasonBackend     = "backend"
	CloseReasonIdleTimeout = "idle_timeout"
	CloseReasonShutdown    = "shutdown"
)

// Close status codes the gateway sends when it ends a connection itself
// (RFC 6455 section 7.4 and the IANA WebSocket close code registry).
const (
	closeGoingAway  = 1001
	closeBadGateway = 1014
)

const (
	opClose = 0x8

	// maxFrameHeader is the largest possible frame header: 2 fixed
	// bytes, an 8-byte extended payload length, and a 4-byte mask key.
	maxFrameHeader = 14

	relayBufferSize = 32 * 1024

	// closeWriteTimeout bounds how long injecting a Close frame may block
	// on a peer that has stopped reading.
	closeWriteTimeout = time.Second

	// idleCloseGrace is how long a connection closed for inactivity gets
	// to complete the closing handshake before it's torn down regardless.
	idleCloseGrace = 2 * time.Second
)

// Endpoint is one side of a proxied connection: the raw connection plus
// the buffered reader already wrapped around it, which may hold frame
// bytes that arrived together with the HTTP handshake and must not be
// lost.
type Endpoint struct {
	Conn   net.Conn
	Reader *bufio.Reader
}

// tunnel relays frames between a client and a backend until either side
// goes away, the connection idles out, or the gateway closes it.
type tunnel struct {
	route       string
	client      Endpoint
	backend     Endpoint
	idleTimeout time.Duration
	opened      time.Time

	// Each mutex serialises whole frames written to one side, so a Close
	// frame the gateway injects never lands inside a relayed frame.
	clientWriteMu  sync.Mutex
	backendWriteMu sync.Mutex

	lastActivity atomic.Int64 // unix nanos of the last relayed frame

	// closing is set once a Close frame has been relayed or injected in
	// either direction; it stops the gateway from injecting another one
	// and, when the gateway itself initiated the close, makes the relays
	// discard everything except the client's answering Close.
	closing         atomic.Bool
	gatewayInitiate atomic.Bool

	reasonMu sync.Mutex
	reason   string

	teardownOnce sync.Once
	done         chan struct{}
}

func newTunnel(route string, client, backend Endpoint, idleTimeout time.Duration) *tunnel {
	t := &tunnel{
		route:       route,
		client:      client,
		backend:     backend,
		idleTimeout: idleTimeout,
		opened:      time.Now(),
		done:        make(chan struct{}),
	}
	t.touch()
	return t
}

// run relays frames in both directions and blocks until the connection
// has been fully torn down, returning why it closed.
func (t *tunnel) run() string {
	finished := make(chan struct{}, 2)
	go func() {
		t.relay(t.client, t.backend.Conn, &t.backendWriteMu, true)
		finished <- struct{}{}
	}()
	go func() {
		t.relay(t.backend, t.client.Conn, &t.clientWriteMu, false)
		finished <- struct{}{}
	}()
	if t.idleTimeout > 0 {
		go t.watchIdle()
	}

	<-finished
	t.teardown()
	<-finished
	return t.closeReason()
}

// relay copies frames from src to dst until src or dst fails. fromClient
// says which direction this is, for attributing the close and for
// recognising the client's reply to a gateway-initiated close.
func (t *tunnel) relay(src Endpoint, dst net.Conn, dstMu *sync.Mutex, fromClient bool) {
	srcSide, dstSide := CloseReasonBackend, CloseReasonClient
	if fromClient {
		srcSide, dstSide = CloseReasonClient, CloseReasonBackend
	}

	buf := make([]byte, relayBufferSize)
	for {
		hlen, payloadLen, err := readFrameHeader(src.Reader, buf)
		if err != nil {
			t.peerGone(srcSide, !fromClient)
			return
		}
		t.touch()
		opcode := buf[0] & 0x0f

		dstMu.Lock()
		if t.gatewayInitiate.Load() {
			// The gateway has already sent its own Close to both sides:
			// nothing further is forwarded. The client's answering Close
			// completes the closing handshake.
			dstMu.Unlock()
			if _, err := io.CopyN(io.Discard, src.Reader, int64(payloadLen)); err != nil {
				return
			}
			if fromClient && opcode == opClose {
				return
			}
			continue
		}
		if opcode == opClose && t.closing.CompareAndSwap(false, true) {
			t.setReason(srcSide)
		}
		readErr, writeErr := copyFrame(dst, src.Reader, buf, hlen, payloadLen)
		dstMu.Unlock()

		switch {
		case readErr != nil:
			t.peerGone(srcSide, !fromClient)
			return
		case writeErr != nil:
			t.peerGone(dstSide, fromClient)
			return
		}
	}
}

// peerGone handles one side's connection ending. If that happened
// without a closing handshake, the other side is sent a Close frame
// (toClient picks which one) so it learns the connection is over cleanly
// rather than from a bare TCP reset.
func (t *tunnel) peerGone(side string, toClient bool) {
	t.setReason(side)
	if !t.closing.CompareAndSwap(false, true) {
		return
	}
	if toClient {
		t.writeClose(t.client.Conn, &t.clientWriteMu, false, closeBadGateway, "backend closed the connection")
	} else {
		t.writeClose(t.backend.Conn, &t.backendWriteMu, true, closeGoingAway, "client closed the connection")
	}
}

// close starts a gateway-initiated close: a Close frame with code and
// text goes to both sides, and the connection is torn down once the
// client answers or grace elapses, whichever comes first. reason is what
// the close is attributed to in metrics. It's a no-op if a close is
// already under way.
func (t *tunnel) close(code int, text, reason string, grace time.Duration) {
	if !t.closing.CompareAndSwap(false, true) {
		return
	}
	t.gatewayInitiate.Store(true)
	t.setReason(reason)

	go func() {
		t.writeClose(t.client.Conn, &t.clientWriteMu, false, code, text)
		t.writeClose(t.backend.Conn, &t.backendWriteMu, true, code, text)
	}()
	go func() {
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case <-t.done:
		case <-timer.C:
			t.teardown()
		}
	}()
}

// writeClose writes a Close frame to conn, masked if it's headed to the
// backend (RFC 6455 requires every client-to-server frame to be masked).
func (t *tunnel) writeClose(conn net.Conn, mu *sync.Mutex, masked bool, code int, text string) {
	mu.Lock()
	defer mu.Unlock()
	_ = conn.SetWriteDeadline(time.Now().Add(closeWriteTimeout))
	_, _ = conn.Write(closeFrame(code, text, masked))
}

// watchIdle closes the connection once no frame has crossed it, in
// either direction, for idleTimeout.
func (t *tunnel) watchIdle() {
	timer := time.NewTimer(t.idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-timer.C:
			idle := time.Since(time.Unix(0, t.lastActivity.Load()))
			if idle >= t.idleTimeout {
				t.close(closeGoingAway, "idle timeout", CloseReasonIdleTimeout, idleCloseGrace)
				return
			}
			timer.Reset(t.idleTimeout - idle)
		}
	}
}

// teardown closes both underlying connections, which unblocks whichever
// relay is still running. Safe to call more than once.
func (t *tunnel) teardown() {
	t.teardownOnce.Do(func() {
		close(t.done)
		_ = t.client.Conn.Close()
		_ = t.backend.Conn.Close()
	})
}

func (t *tunnel) touch() {
	t.lastActivity.Store(time.Now().UnixNano())
}

// setReason records why the connection closed. The first reason wins.
func (t *tunnel) setReason(reason string) {
	t.reasonMu.Lock()
	defer t.reasonMu.Unlock()
	if t.reason == "" {
		t.reason = reason
	}
}

func (t *tunnel) closeReason() string {
	t.reasonMu.Lock()
	defer t.reasonMu.Unlock()
	return t.reason
}

// readFrameHeader reads one complete frame header from r into buf and
// returns its length and the frame's payload length.
func readFrameHeader(r *bufio.Reader, buf []byte) (hlen int, payloadLen uint64, err error) {
	if _, err := io.ReadFull(r, buf[:2]); err != nil {
		return 0, 0, err
	}
	extLen := 0
	switch l := buf[1] & 0x7f; l {
	case 126:
		extLen = 2
	case 127:
		extLen = 8
	default:
		payloadLen = uint64(l)
	}
	maskLen := 0
	if buf[1]&0x80 != 0 {
		maskLen = 4
	}
	hlen = 2 + extLen + maskLen
	if _, err := io.ReadFull(r, buf[2:hlen]); err != nil {
		return 0, 0, err
	}
	switch extLen {
	case 2:
		payloadLen = uint64(binary.BigEndian.Uint16(buf[2:4]))
	case 8:
		payloadLen = binary.BigEndian.Uint64(buf[2:10])
		if payloadLen > 1<<63-1 {
			return 0, 0, errFrameTooLarge
		}
	}
	return hlen, payloadLen, nil
}

var errFrameTooLarge = errors.New("websocket: frame payload length exceeds 2^63-1")

// copyFrame writes the header already in buf[:hlen] followed by
// payloadLen bytes streamed from src, reusing buf so small frames go out
// in a single write. It reports a read failure (src went away) separately
// from a write failure (dst went away).
func copyFrame(dst io.Writer, src io.Reader, buf []byte, hlen int, payloadLen uint64) (readErr, writeErr error) {
	n := hlen
	remaining := payloadLen
	for {
		if remaining > 0 && n < len(buf) {
			want := uint64(len(buf) - n)
			if remaining < want {
				want = remaining
			}
			read, err := src.Read(buf[n : n+int(want)])
			n += read
			remaining -= uint64(read)
			if err != nil && remaining > 0 {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return err, nil
			}
		}
		if n == len(buf) || remaining == 0 {
			if _, err := dst.Write(buf[:n]); err != nil {
				return nil, err
			}
			n = 0
			if remaining == 0 {
				return nil, nil
			}
		}
	}
}

// closeFrame builds a final Close frame carrying code and text (truncated
// to fit the 125-byte control frame limit), masked with a random key if
// masked is true.
func closeFrame(code int, text string, masked bool) []byte {
	if len(text) > 123 {
		text = text[:123]
	}
	payload := make([]byte, 2+len(text))
	binary.BigEndian.PutUint16(payload, uint16(code))
	copy(payload[2:], text)

	frame := []byte{0x80 | opClose, byte(len(payload))}
	if masked {
		var key [4]byte
		_, _ = rand.Read(key[:])
		frame[1] |= 0x80
		frame = append(frame, key[:]...)
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return append(frame, payload...)
}
