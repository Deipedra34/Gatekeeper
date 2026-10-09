// Package wstest is a deliberately small WebSocket (RFC 6455) client and
// server used by Gatekeeper's tests and the scripts/wsclient demo. It
// speaks just enough of the protocol to drive the proxy end to end —
// single-frame messages, Close/Ping/Pong — without pulling a WebSocket
// library into the module. It is not meant for production traffic.
package wstest

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Opcodes.
const (
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	OpPing   = 0x9
	OpPong   = 0xA
)

const acceptGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// ErrBadHandshake is returned by Dial when the server answers the upgrade
// request with anything other than a valid 101 Switching Protocols.
var ErrBadHandshake = errors.New("wstest: bad handshake")

// Conn is one end of a WebSocket connection. Writes are safe for
// concurrent use; reads must come from a single goroutine.
type Conn struct {
	conn     net.Conn
	br       *bufio.Reader
	isClient bool
	wmu      sync.Mutex
}

// Dial opens a WebSocket connection to rawURL (ws://, wss://, http:// or
// https://), sending header along with the upgrade request. On a non-101
// answer it returns the response — body already read and closed, its
// text available via ResponseBody — along with ErrBadHandshake.
func Dial(rawURL string, header http.Header) (*Conn, *http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	useTLS := false
	switch u.Scheme {
	case "ws", "http":
	case "wss", "https":
		useTLS = true
	default:
		return nil, nil, fmt.Errorf("wstest: unsupported scheme %q", u.Scheme)
	}
	addr := u.Host
	if u.Port() == "" {
		if useTLS {
			addr = net.JoinHostPort(u.Hostname(), "443")
		} else {
			addr = net.JoinHostPort(u.Hostname(), "80")
		}
	}

	var conn net.Conn
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: u.Hostname()})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, nil, err
	}

	key := newKey()
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Path: u.Path, RawPath: u.RawPath, RawQuery: u.RawQuery},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       u.Host,
	}
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", key)

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != acceptKey(key) {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
		conn.Close()
		return nil, resp, ErrBadHandshake
	}
	_ = conn.SetDeadline(time.Time{})
	return &Conn{conn: conn, br: br, isClient: true}, resp, nil
}

// ResponseBody reads a handshake response's body as a string.
func ResponseBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// Upgrade completes the server side of a WebSocket handshake on w,
// hijacking the underlying connection. Headers already set on w (e.g.
// Sec-WebSocket-Protocol) are included in the 101 response.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		http.Error(w, "not a websocket handshake", http.StatusBadRequest)
		return nil, errors.New("wstest: not a websocket handshake")
	}
	header := w.Header().Clone()
	header.Set("Upgrade", "websocket")
	header.Set("Connection", "Upgrade")
	header.Set("Sec-WebSocket-Accept", acceptKey(key))

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	if _, err := brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); err != nil {
		conn.Close()
		return nil, err
	}
	if err := header.Write(brw); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := brw.WriteString("\r\n"); err != nil {
		conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &Conn{conn: conn, br: brw.Reader}, nil
}

// EchoHandler upgrades every request and echoes each text or binary
// message straight back, answers pings, and completes the closing
// handshake when the peer sends Close.
func EchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := Upgrade(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			op, payload, err := c.ReadMessage()
			if err != nil {
				return
			}
			switch op {
			case OpText, OpBinary:
				if c.WriteMessage(op, payload) != nil {
					return
				}
			case OpPing:
				_ = c.WriteMessage(OpPong, payload)
			case OpClose:
				_ = c.WriteMessage(OpClose, payload)
				return
			}
		}
	})
}

// WriteMessage sends payload as a single final frame with opcode op.
func (c *Conn) WriteMessage(op byte, payload []byte) error {
	header := []byte{0x80 | op, 0}
	n := len(payload)
	switch {
	case n <= 125:
		header[1] = byte(n)
	case n <= 0xFFFF:
		header[1] = 126
		header = binary.BigEndian.AppendUint16(header, uint16(n))
	default:
		header[1] = 127
		header = binary.BigEndian.AppendUint64(header, uint64(n))
	}
	body := payload
	if c.isClient {
		var mask [4]byte
		_, _ = rand.Read(mask[:])
		header[1] |= 0x80
		header = append(header, mask[:]...)
		body = make([]byte, n)
		for i := range payload {
			body[i] = payload[i] ^ mask[i%4]
		}
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.conn.Write(append(header, body...))
	return err
}

// WriteText sends s as a text message.
func (c *Conn) WriteText(s string) error { return c.WriteMessage(OpText, []byte(s)) }

// WriteClose sends a Close frame with code and reason.
func (c *Conn) WriteClose(code int, reason string) error {
	payload := binary.BigEndian.AppendUint16(nil, uint16(code))
	return c.WriteMessage(OpClose, append(payload, reason...))
}

// ReadMessage reads one frame and returns its opcode and unmasked
// payload. Fragmented messages are returned frame by frame.
func (c *Conn) ReadMessage() (op byte, payload []byte, err error) {
	var h [2]byte
	if _, err := io.ReadFull(c.br, h[:]); err != nil {
		return 0, nil, err
	}
	op = h[0] & 0x0f
	length := uint64(h[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.br, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > 64<<20 {
		return 0, nil, errors.New("wstest: frame too large")
	}
	var mask [4]byte
	masked := h[1]&0x80 != 0
	if masked {
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return op, payload, nil
}

// ReadText reads the next message and returns it as a string, failing if
// it isn't a text message.
func (c *Conn) ReadText() (string, error) {
	op, payload, err := c.ReadMessage()
	if err != nil {
		return "", err
	}
	if op != OpText {
		return "", fmt.Errorf("wstest: expected text frame, got opcode %#x (payload %q)", op, payload)
	}
	return string(payload), nil
}

// CloseCode parses a Close frame payload into its status code and reason.
func CloseCode(payload []byte) (int, string) {
	if len(payload) < 2 {
		return 1005, "" // no status code present
	}
	return int(binary.BigEndian.Uint16(payload)), string(payload[2:])
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// Close closes the underlying connection without a closing handshake.
func (c *Conn) Close() error { return c.conn.Close() }

func newKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

func acceptKey(key string) string {
	sum := sha1.Sum([]byte(key + acceptGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}
