package protocol

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// CapabilitySyncGzip says the agent can exchange /v1/node/sync bodies compressed
// with gzip. It is not an upgrade capability.
//
// WHY IT EXISTS. MaxSyncBodyBytes bounds the raw JSON of one body, and the
// roster is sent whole whenever it changes, so a server's client count had a
// ceiling set by the size of its roster. Roster JSON is highly repetitive and
// compresses many times over, so the cure is to bound what travels (the wire
// limit) separately from what is held in memory (the decoded limit).
//
// NEGOTIATION. Both ends must say so, and neither guesses:
//
//   - The agent declares the capability in NodeReport.Capabilities. Its first
//     report is plain, because it cannot yet know the panel accepts anything
//     else. PSP may then answer with Content-Encoding: gzip, and only to an
//     agent that declared it.
//   - PSP says it accepts compressed requests with an Accept-Encoding header
//     containing gzip on its responses (SyncAcceptEncodingHeader; RFC 9110
//     lets a server do this for request codings). An agent sends a compressed
//     request only after a response carried it, and only if it declared the
//     capability.
//
// A peer that never declared it sees byte-identical behaviour to v0.8.x:
// plain bodies bounded by MaxSyncBodyBytes, in both directions. A receiver
// refuses a Content-Encoding it did not negotiate, which DecodeSyncBody leaves
// to the caller because only the caller knows what was negotiated.
//
// The ETag of a segment is taken over the canonical decoded bytes, so
// compression never changes a validator.
const CapabilitySyncGzip = "sync.gzip.v1"

// The sync content codings and the header that carries them.
const (
	SyncEncodingIdentity = "identity"
	SyncEncodingGzip     = "gzip"
	// SyncContentEncodingHeader names the coding of a body.
	SyncContentEncodingHeader = "Content-Encoding"
	// SyncAcceptEncodingHeader is how PSP says, on a response, that it accepts
	// gzip request bodies.
	SyncAcceptEncodingHeader = "Accept-Encoding"
)

const (
	// MaxSyncWireBytes is what may cross the wire in one body, plain or
	// compressed. It is the value MaxSyncBodyBytes always was; a body without a
	// Content-Encoding is held to it exactly as before.
	MaxSyncWireBytes = MaxSyncBodyBytes
	// MaxSyncDecodedBytes bounds a body after decompression. It is four times
	// the wire limit: roster JSON repeats its keys in every client, so it
	// routinely shrinks by an order of magnitude, and 4x leaves headroom over
	// that without letting a ratio of a thousand (what a bomb achieves, and what
	// a trivially repetitive document legitimately does) turn 16 MiB of input
	// into gigabytes. A decoded body of N bytes is transiently held about twice
	// (the chunks and the joined result), so the ceiling costs about 128 MiB at
	// the join, and parsing the JSON then costs several times N on top. That is
	// what a small agent host can afford for one body; a receiver that decodes
	// several at once (PSP) must bound concurrent decodes itself. It is a
	// ceiling, not an allowance: the decoder allocates what it reads.
	MaxSyncDecodedBytes = int64(64 << 20)
)

var (
	// ErrSyncWireTooLarge: the body on the wire exceeds the wire limit.
	ErrSyncWireTooLarge = errors.New("sync body exceeds the wire size limit")
	// ErrSyncDecodedTooLarge: the body is larger than the decoded limit once
	// decompressed.
	ErrSyncDecodedTooLarge = errors.New("sync body exceeds the decoded size limit")
	// ErrSyncUnknownEncoding: a Content-Encoding other than none, identity or gzip.
	ErrSyncUnknownEncoding = errors.New("unknown sync content encoding")
)

// NormalizeSyncEncoding maps a Content-Encoding header value to
// SyncEncodingIdentity or SyncEncodingGzip. An empty value is identity. A list
// ("gzip, gzip"), a parameter or any other coding is ErrSyncUnknownEncoding.
func NormalizeSyncEncoding(encoding string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", SyncEncodingIdentity:
		return SyncEncodingIdentity, nil
	case SyncEncodingGzip:
		return SyncEncodingGzip, nil
	}
	return "", fmt.Errorf("%w %q", ErrSyncUnknownEncoding, encoding)
}

// SyncEncodingFromHeaders is NormalizeSyncEncoding for the values of every
// Content-Encoding header of a message. HTTP lets a header repeat, and a
// caller that reads only the first value (Header.Get) would decode a body whose
// later coding it never saw. Two headers are refused whatever they say, as is
// a list inside one.
func SyncEncodingFromHeaders(values []string) (string, error) {
	switch len(values) {
	case 0:
		return SyncEncodingIdentity, nil
	case 1:
		return NormalizeSyncEncoding(values[0])
	}
	return "", fmt.Errorf("%w: %d Content-Encoding headers", ErrSyncUnknownEncoding, len(values))
}

// SyncGzipCooldown is how long an agent stays plain after the panel rejected a
// compressed request (see SyncCompression).
const SyncGzipCooldown = time.Hour

// SyncCompression is the agent's side of the negotiation, as a state machine.
//
//   - It starts plain. Outside a cooldown a 2xx response REPLACES the state:
//     ObserveResponse takes its Accept-Encoding header, and an absent header
//     means plain. A response that is not 2xx, and a request that got no
//     response at all, leave the state as it was: an error page or a dropped
//     connection says nothing about what the panel accepts.
//   - A request is compressed only when the agent declared CapabilitySyncGzip,
//     the state says gzip and no cooldown is running.
//   - A non-2xx answer to a compressed request may be a refusal of the coding
//     (a panel without gzip answers 400 or 415; a WAF or proxy that passes
//     plain POSTs may answer 403, 406, 411, 501, ...) or may have nothing to do
//     with it. Rejected says whether to resend the SAME request once in plain:
//     yes for any non-2xx except the transients (408, 429, 500, 502, 503, 504
//     and the 520-530 a CDN answers while the origin is unreachable: the panel
//     is slow, busy, restarting or down) and 401/407 (credentials: the plain
//     resend would fail the same way). Rejected changes nothing.
//   - The plain resend decides (PlainRetried). If it succeeds, the coding was
//     the problem: gzip stays off for SyncGzipCooldown. If it fails too, the
//     coding was not the problem and nothing changes, so an unrelated refusal
//     (a report the panel found invalid, a truncated body) never costs an hour
//     without compression, which for a report that fits a proxy's limit only
//     compressed would be an hour without sync.
//   - During the cooldown an advertisement is ignored (the plain resend's own
//     2xx would otherwise switch gzip straight back on), but a 2xx WITHOUT one
//     still switches it off: a panel rolled back to one without gzip stops
//     getting compressed requests. When the cooldown ends the agent tries gzip
//     again on what it last learned, without waiting for a fresh advertisement.
//
// The clock is a parameter so that tests can move it. It is not safe for
// concurrent use.
type SyncCompression struct {
	declared bool
	accepts  bool
	now      func() time.Time
	until    time.Time
}

// NewSyncCompression starts a plain session. declared is whether the agent put
// CapabilitySyncGzip in its reports; now is the clock, time.Now when nil.
func NewSyncCompression(declared bool, now func() time.Time) *SyncCompression {
	if now == nil {
		now = time.Now
	}
	return &SyncCompression{declared: declared, now: now}
}

// RequestEncoding is the Content-Encoding to send the next request with:
// SyncEncodingGzip or "" for plain.
func (c *SyncCompression) RequestEncoding() string {
	if c.declared && c.accepts && !c.cooling() {
		return SyncEncodingGzip
	}
	return ""
}

func (c *SyncCompression) cooling() bool { return c.now().Before(c.until) }

// ObserveResponse records a response: its status and its Accept-Encoding header
// (empty when absent). Only a 2xx changes the state. During a cooldown it can
// only switch gzip off, never on.
func (c *SyncCompression) ObserveResponse(status int, acceptEncoding string) {
	if status < 200 || status > 299 {
		return
	}
	accepts := AcceptsSyncGzip(acceptEncoding)
	if c.cooling() && accepts {
		return
	}
	c.accepts = accepts
}

// Rejected is called with the status of a response to a request sent with
// sentEncoding, and says whether to resend that request once in plain: true
// for a gzip request answered with a non-2xx status other than the transients
// and 401/407 (see SyncCompression). It changes no state; PlainRetried does,
// with the outcome of the resend.
func (c *SyncCompression) Rejected(status int, sentEncoding string) bool {
	if sentEncoding != SyncEncodingGzip || (status >= 200 && status <= 299) || syncTransient(status) {
		return false
	}
	switch status {
	case 401, 407:
		return false
	}
	return true
}

// PlainRetried records the status of the plain resend Rejected asked for. A 2xx
// proves the coding was refused and starts SyncGzipCooldown; anything else
// leaves the state as it was. Call it before ObserveResponse for the same
// response, so the resend's own advertisement falls inside the cooldown.
func (c *SyncCompression) PlainRetried(status int) {
	if status >= 200 && status <= 299 {
		c.until = c.now().Add(SyncGzipCooldown)
	}
}

// syncTransient reports a status that says the panel is slow, busy, restarting
// or unreachable rather than that the path refuses a coding: 408, 429, 500,
// 502, 503, 504, and 520-530, which CDNs (Cloudflare among them) answer when the
// origin cannot be reached.
func syncTransient(status int) bool {
	switch status {
	case 408, 429, 500, 502, 503, 504:
		return true
	}
	return status >= 520 && status <= 530
}

// AcceptsSyncGzip reads an Accept-Encoding header value and says whether it
// offers gzip: the token must be present and not refused with q=0.
func AcceptsSyncGzip(acceptEncoding string) bool {
	for _, item := range strings.Split(acceptEncoding, ",") {
		coding, params, _ := strings.Cut(item, ";")
		if strings.ToLower(strings.TrimSpace(coding)) != SyncEncodingGzip {
			continue
		}
		for _, param := range strings.Split(params, ";") {
			name, value, _ := strings.Cut(param, "=")
			if strings.ToLower(strings.TrimSpace(name)) != "q" {
				continue
			}
			// q=0, q=0., q=0.000 refuse the coding, and so does a weight that is
			// not a finite number in (0, 1] (NaN, inf and 1.5 are not offers).
			weight, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil || math.IsNaN(weight) || math.IsInf(weight, 0) || weight <= 0 || weight > 1 {
				return false
			}
		}
		return true
	}
	return false
}

// EncodeSyncBody compresses a body for the wire with gzip. It refuses a body
// above MaxSyncDecodedBytes, which no peer would accept, and a result above
// MaxSyncWireBytes. The output carries no timestamp or name, so the same input
// gives the same bytes from the same Go release. Callers send it with
// Content-Encoding: gzip.
func EncodeSyncBody(body []byte) ([]byte, error) {
	return encodeSyncBody(body, MaxSyncWireBytes, MaxSyncDecodedBytes)
}

func encodeSyncBody(body []byte, wireLimit, decodedLimit int64) ([]byte, error) {
	if int64(len(body)) > decodedLimit {
		return nil, ErrSyncDecodedTooLarge
	}
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(body); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if int64(out.Len()) > wireLimit {
		return nil, ErrSyncWireTooLarge
	}
	return out.Bytes(), nil
}

// DecodeSyncBody reads one sync body from r under MaxSyncWireBytes and
// MaxSyncDecodedBytes and returns the decoded bytes. encoding is the
// Content-Encoding header value.
//
// A body with no coding (or identity) is held to the wire limit, as it always
// was. A gzip body is held to the wire limit on the compressed bytes read and
// to the decoded limit on the output, enforced as it streams: input that would
// expand past the limit is refused after limit+1 bytes of output, and the rest
// of the stream is never inflated, so a zip bomb costs the receiver about its
// limit and not the bomb's size. The gzip
// stream must be complete and valid; trailing garbage is refused.
//
// Whether the coding was negotiated is the caller's check: DecodeSyncBody
// decodes what it is given.
func DecodeSyncBody(r io.Reader, encoding string) ([]byte, error) {
	return decodeSyncBody(r, encoding, MaxSyncWireBytes, MaxSyncDecodedBytes)
}

func decodeSyncBody(r io.Reader, encoding string, wireLimit, decodedLimit int64) ([]byte, error) {
	coding, err := NormalizeSyncEncoding(encoding)
	if err != nil {
		return nil, err
	}
	wire := &wireLimitReader{r: r, remaining: wireLimit}
	if coding == SyncEncodingIdentity {
		return readLimited(wire, wireLimit, ErrSyncWireTooLarge)
	}
	reader, err := gzip.NewReader(wire)
	if err != nil {
		if wire.exceeded {
			return nil, ErrSyncWireTooLarge
		}
		return nil, fmt.Errorf("sync body is not valid gzip: %w", err)
	}
	defer reader.Close()
	body, err := readLimited(reader, decodedLimit, ErrSyncDecodedTooLarge)
	if wire.exceeded {
		return nil, ErrSyncWireTooLarge
	}
	if err != nil {
		if errors.Is(err, ErrSyncDecodedTooLarge) {
			return nil, err
		}
		return nil, fmt.Errorf("sync body is not valid gzip: %w", err)
	}
	return body, nil
}

// wireLimitReader fails, rather than truncates, when the source has more than
// remaining bytes, so a body that is exactly at the limit is accepted and one
// byte over is not.
type wireLimitReader struct {
	r         io.Reader
	remaining int64
	exceeded  bool
}

func (w *wireLimitReader) Read(p []byte) (int, error) {
	if w.exceeded {
		return 0, ErrSyncWireTooLarge
	}
	// One byte beyond the limit is read so that "exactly the limit" and "over"
	// differ.
	if int64(len(p)) > w.remaining+1 {
		p = p[:w.remaining+1]
	}
	n, err := w.r.Read(p)
	if int64(n) > w.remaining {
		w.exceeded = true
		n = int(w.remaining)
		w.remaining = 0
		return n, ErrSyncWireTooLarge
	}
	w.remaining -= int64(n)
	return n, err
}

// readLimited reads r to EOF and returns tooLarge when it holds more than limit
// bytes. It reads into chunks (at most 1 MiB each) and joins them once, so the
// bytes held are never more than the chunks plus the result: twice the body at
// the join, and never a doubling buffer's old and new copies at once. A source
// that exceeds the limit is refused after limit+1 bytes, before any join.
func readLimited(r io.Reader, limit int64, tooLarge error) ([]byte, error) {
	const maxChunk = 1 << 20
	var chunks [][]byte
	var total int64
	chunk := make([]byte, 0, 32<<10)
	for {
		if len(chunk) == cap(chunk) {
			chunks = append(chunks, chunk)
			next := cap(chunk) * 2
			if next > maxChunk {
				next = maxChunk
			}
			chunk = make([]byte, 0, next)
		}
		// Never ask for more than limit+1 bytes in all.
		room := chunk[len(chunk):cap(chunk)]
		if int64(len(room)) > limit+1-total {
			room = room[:limit+1-total]
		}
		n, err := r.Read(room)
		chunk = chunk[:len(chunk)+n]
		total += int64(n)
		if total > limit {
			return nil, tooLarge
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, ErrSyncWireTooLarge) {
				return nil, ErrSyncWireTooLarge
			}
			return nil, err
		}
	}
	chunks = append(chunks, chunk)
	body := make([]byte, 0, total)
	for i, part := range chunks {
		body = append(body, part...)
		chunks[i] = nil
	}
	return body, nil
}
