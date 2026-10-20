package transport

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"time"
)

// The decoy site is built in memory; the sample never reads fallback_dir for
// it (REPORT.md §7.9, notes/rev-transport.md §7.1: newDecoySite 0xaae760 is
// fed by rodata HTML fragments, and decoyFile is a thin wrapper over a byte
// slice with no file handle).

// errWebPage is the HTML error document shared by the panel and the transport
// (REPORT.md §7.9: "403 Forbidden"/"404" wording shares the constant pool with
// panel.errWebPage).
const errWebPage = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>%d %s</title>
<style>%s</style></head>
<body><h1>%d %s</h1><p>%s</p></body>
</html>
`

// decoyCSS is the inline style of the in-memory default page
// (notes/rev-transport.md §7.1, rodata 0xfa5793).
const decoyCSS = `html{height:100%}body{display:flex;align-items:center;justify-content:center;height:100%;margin:0;font-family:system-ui,sans-serif}`

// errCSS is the style used for the error pages (rodata, "body { background:
// #fafafa; color: #222; font: 16px/1.5 Georgia, serif; margin: 3em; }").
const errCSS = `body { background: #fafafa; color: #222; font: 16px/1.5 Georgia, serif; margin: 3em; }`

// decoyHTML is the nginx-style default page the sample assembles from rodata
// fragments: title "Welcome - Home", an <h1>Index</h1>, <h2>Hello</h2> and the
// classic "It works!" paragraph (notes/rev-transport.md §7.1 table).
const decoyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome - Home</title>
<style>` + decoyCSS + `</style>
</head>
<body>
<h1>Index</h1>
<h2>Hello</h2>
<p>It works!</p>
</body>
</html>
`

// errorPage renders the sample's HTML error document.
func errorPage(code int, msg string) []byte {
	if msg == "" {
		msg = http.StatusText(code)
	}
	return []byte(sprintfPage(code, http.StatusText(code), msg))
}

func sprintfPage(code int, status, msg string) string {
	return "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>" +
		itoa(code) + " " + status + "</title>\n<style>" + errCSS + "</style></head>\n<body><h1>" +
		itoa(code) + " " + status + "</h1><p>" + msg + "</p></body>\n</html>\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// decoyFile is one in-memory file of the decoy site. It implements the
// io.ReadSeeker/io.ByteReader/io.RuneReader/io.WriterTo surface the sample's
// decoyFile exposes (Seek 0xad00e0, WriteTo 0xad0580, ...).
type decoyFile struct {
	name string
	data []byte
	off  int64
}

func (f *decoyFile) Name() string       { return f.name }
func (f *decoyFile) Len() int           { return len(f.data) }
func (f *decoyFile) Size() int64        { return int64(len(f.data)) }
func (f *decoyFile) Mode() uint32       { return 0 }
func (f *decoyFile) ModTime() time.Time { return time.Time{} }
func (f *decoyFile) IsDir() bool        { return false }

func (f *decoyFile) Read(p []byte) (int, error) {
	if f.off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.off:])
	f.off += int64(n)
	return n, nil
}

func (f *decoyFile) ReadByte() (byte, error) {
	if f.off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	b := f.data[f.off]
	f.off++
	return b, nil
}

func (f *decoyFile) UnreadByte() error {
	if f.off == 0 {
		return errors.New("bytes.Buffer: UnreadByte: previous operation was not a successful Read")
	}
	f.off--
	return nil
}

func (f *decoyFile) ReadRune() (rune, int, error) {
	if f.off >= int64(len(f.data)) {
		return 0, 0, io.EOF
	}
	r := rune(f.data[f.off])
	f.off++
	return r, 1, nil
}

func (f *decoyFile) UnreadRune() error {
	if f.off == 0 {
		return errors.New("bytes.Buffer: UnreadRune: previous operation was not a successful ReadRune")
	}
	f.off--
	return nil
}

func (f *decoyFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += f.off
	case io.SeekEnd:
		offset += int64(len(f.data))
	}
	if offset < 0 || offset > int64(len(f.data)) {
		return 0, errors.New("negative position")
	}
	f.off = offset
	return offset, nil
}

func (f *decoyFile) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(f.data[f.off:])
	f.off += int64(n)
	return int64(n), err
}

func (f *decoyFile) Close() error { return nil }

// decoySite is the in-memory site (the sample's decoySite/decoyDir).
type decoySite struct{}

// newDecoySite builds the default page. It takes no directory argument: the
// page is assembled from constants, like the sample.
func newDecoySite() *decoySite { return &decoySite{} }

func (s *decoySite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "", "/", "/index.html", "/index.htm":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(decoyHTML))
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(errorPage(http.StatusNotFound, "The requested URL was not found on this server."))
	}
}

func (s *decoySite) open(name string) (*decoyFile, bool) {
	switch name {
	case "", "/", "/index.html", "/index.htm":
		return &decoyFile{name: "index.html", data: []byte(decoyHTML)}, true
	}
	return nil, false
}

func (s *decoySite) readFile(name string) ([]byte, bool) {
	if f, ok := s.open(name); ok {
		return f.data, true
	}
	return nil, false
}

// bytesReader is a small helper so callers can replay the decoy page.
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
