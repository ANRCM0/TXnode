package transport

// REALITY mirror (reality_mirror: on | shape | off).
//
// The sample learns what the borrowed site answers to a REALITY-shaped hello and
// uses that answer as the shape it shows to clients it refuses:
//
//	transport.newMirror                build the cache
//	transport.(*mirror).mayLearn       decide whether a probe may refresh it
//	transport.(*mirror).ask/askAs      send a hello to the site, read the answer
//	transport.(*mirror).learn          store the first flight and its duration
//	transport.(*mirror).answerFor      shape the refusal answer
//
// Error strings recovered from the binary (catalog-strings):
//
//	the site did not answer the hello (%w)
//	the site did not answer with a ServerHello
//	the site sent a record of type %d in its handshake
//	the site's first flight was not seen
//	reality: record too long / reality: malformed alert
//	REALITY: too large
//	it is %s away, more than the %s the node will make its own clients wait to
//	match: a site nearer to this machine hides the node better
//
// What is implemented here: the learning half (probe the site, remember the
// first flight and its round-trip time, refresh on demand) and the refusal
// half (when mirror is on, hold the relay start until the learned latency has
// elapsed, so the node's answer takes as long as the site's would). Replaying
// the learned bytes verbatim is deliberately NOT done: a cached ServerHello
// cannot complete a handshake without the site's key, so replaying it would
// produce a second, broken ServerHello on the same connection.
//
// UNVERIFIED: whether the sample itself replays the bytes or only shapes the
// timing; the 50 ms "near enough" threshold below is our reading of the
// distance message.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// mirrorMaxWait bounds how long a refusal may be delayed to imitate the site.
const mirrorMaxWait = 2 * time.Second

// mirrorFlight is one learned answer.
type mirrorFlight struct {
	first []byte        // the site's first TLS record, verbatim
	rtt   time.Duration // how long the site took to produce it
	at    time.Time
}

// mirror is the cache behind reality_mirror.
type mirror struct {
	mu     sync.Mutex
	flight *mirrorFlight
	// ttl keeps a learned answer usable; the sample refreshes lazily.
	ttl time.Duration
	// now is a test seam.
	now func() time.Time
}

func newMirror() *mirror {
	return &mirror{ttl: 10 * time.Minute, now: time.Now}
}

// mayLearn reports whether a probe is allowed to refresh the cache.
func (m *mirror) mayLearn() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.flight == nil {
		return true
	}
	return m.now().Sub(m.flight.at) >= m.ttl
}

// learn asks the site for a handshake and stores the first flight.
func (m *mirror) learn(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), dest string) error {
	if dial == nil || dest == "" {
		return errors.New("the site did not answer the hello (no dialer)")
	}
	hello, err := syntheticClientHello()
	if err != nil {
		return err
	}
	start := m.now()
	conn, err := dial(ctx, "tcp", dest)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(5 * time.Second))
	if _, err := conn.Write(hello); err != nil {
		return err
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return errors.New("the site did not answer the hello")
	}
	switch hdr[0] {
	case 0x15:
		ab := make([]byte, 2)
		_, _ = io.ReadFull(conn, ab)
		return errors.New("reality: malformed alert (level " + itoaByte(ab[0]) + " desc " + itoaByte(ab[1]) + ")")
	case 0x16:
	default:
		return errors.New("the site sent a record of type " + itoaByte(hdr[0]) + " in its handshake")
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	if n <= 0 || n > 0x4000 {
		return errors.New("reality: record too long")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return errors.New("the site's first flight was not seen")
	}
	elapsed := m.now().Sub(start)
	m.mu.Lock()
	m.flight = &mirrorFlight{first: append(hdr, body...), rtt: elapsed, at: m.now()}
	m.mu.Unlock()
	return nil
}

// answerFor returns how long a refusal should wait before relaying, so that the
// node's answer has the borrowed site's timing. mode is the configured
// reality_mirror value ("on", "shape" or "off").
func (m *mirror) answerFor(mode string) time.Duration {
	switch mode {
	case "on", "shape":
	default:
		return 0
	}
	m.mu.Lock()
	f := m.flight
	m.mu.Unlock()
	if f == nil || f.rtt <= 0 {
		return 0
	}
	d := f.rtt
	if d > mirrorMaxWait {
		d = mirrorMaxWait
	}
	return d
}

// syntheticClientHello produces a real ClientHello record by letting uTLS
// build a Chrome fingerprint and capturing the first flight. The sample probes
// the borrowed site with uTLS-shaped hellos (REPORT.md §7.4), so the shape is
// the same one it presents to clients.
func syntheticClientHello() ([]byte, error) {
	c := &captureConn{}
	cfg := &utls.Config{
		ServerName:         "mirror.probe",
		InsecureSkipVerify: true,
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
	}
	uc := utls.UClient(c, cfg, utls.HelloChrome_Auto)
	go func() { _ = uc.Handshake() }()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.buf)
		c.mu.Unlock()
		if n > 5 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	c.mu.Lock()
	out := append([]byte(nil), c.buf...)
	c.mu.Unlock()
	_ = uc.Close()
	if len(out) < 6 {
		return nil, errors.New("the site did not answer the hello (no ClientHello)")
	}
	return out, nil
}

// captureConn records everything written to it and blocks on reads.
type captureConn struct {
	mu  sync.Mutex
	buf []byte
}

func (c *captureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf = append(c.buf, p...)
	c.mu.Unlock()
	return len(p), nil
}
func (c *captureConn) Read([]byte) (int, error)         { time.Sleep(10 * time.Millisecond); return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return nil }
func (c *captureConn) RemoteAddr() net.Addr             { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

func itoaByte(b byte) string {
	if b == 0 {
		return "0"
	}
	var out [3]byte
	i := len(out)
	for b > 0 {
		i--
		out[i] = '0' + b%10
		b /= 10
	}
	return string(out[i:])
}
