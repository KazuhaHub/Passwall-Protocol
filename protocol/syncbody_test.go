package protocol

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSyncGzipCapability(t *testing.T) {
	if CapabilitySyncGzip != "sync.gzip.v1" {
		t.Fatalf("capability name changed: %q", CapabilitySyncGzip)
	}
	for _, upgrade := range AgentUpgradeCapabilities() {
		if upgrade == CapabilitySyncGzip {
			t.Fatalf("%s is an upgrade capability", upgrade)
		}
	}
	if MaxSyncWireBytes != MaxSyncBodyBytes {
		t.Fatalf("the wire limit moved from %d to %d", MaxSyncBodyBytes, MaxSyncWireBytes)
	}
	if MaxSyncDecodedBytes != 64<<20 {
		t.Fatalf("the decoded limit moved to %d", MaxSyncDecodedBytes)
	}
	if MaxSyncDecodedBytes <= MaxSyncWireBytes {
		t.Fatal("the decoded limit must exceed the wire limit")
	}
}

func rosterLikeBody(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"clients":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"key":"cli_`)
		b.WriteString(strings.Repeat("7", 1+i%6))
		b.WriteString(`","subject":"usr_1","listeners":["lst_1","lst_2"],"enabled":true,"expires_at_ms":0,"credentials":{"uuid":"0f62f495-b5ca-4509-b6cd-54a040deafd5"}}`)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

func TestSyncBodyRoundTrip(t *testing.T) {
	body := rosterLikeBody(2000)
	encoded, err := EncodeSyncBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= len(body)/4 {
		t.Fatalf("a roster did not compress: %d -> %d", len(body), len(encoded))
	}
	for _, encoding := range []string{"gzip", "GZIP", " gzip "} {
		got, err := DecodeSyncBody(bytes.NewReader(encoded), encoding)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("encoding %q: round trip failed: %v", encoding, err)
		}
	}
	again, _ := EncodeSyncBody(body)
	if !bytes.Equal(encoded, again) {
		t.Fatal("encoding is not deterministic")
	}
	empty, err := EncodeSyncBody(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeSyncBody(bytes.NewReader(empty), "gzip"); err != nil || len(got) != 0 {
		t.Fatalf("empty body: %q, %v", got, err)
	}
}

// A body with no coding is held to the wire limit exactly as it was before the
// capability: byte-identical behaviour for a peer that never negotiated.
func TestSyncBodyIdentityKeepsTheOldLimit(t *testing.T) {
	body := rosterLikeBody(50)
	for _, encoding := range []string{"", "identity", "Identity"} {
		got, err := DecodeSyncBody(bytes.NewReader(body), encoding)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("encoding %q: %v", encoding, err)
		}
	}
	at := bytes.Repeat([]byte{'a'}, 1000)
	if got, err := decodeSyncBody(bytes.NewReader(at), "", 1000, 1<<30); err != nil || len(got) != 1000 {
		t.Fatalf("a plain body exactly at the limit: %d, %v", len(got), err)
	}
	over := bytes.Repeat([]byte{'a'}, 1001)
	if _, err := decodeSyncBody(bytes.NewReader(over), "", 1000, 1<<30); !errors.Is(err, ErrSyncWireTooLarge) {
		t.Fatalf("a plain body one byte over: %v", err)
	}
	// The decoded limit never loosens a plain body.
	if _, err := decodeSyncBody(bytes.NewReader(over), "identity", 1000, 1<<30); !errors.Is(err, ErrSyncWireTooLarge) {
		t.Fatalf("a plain body is bounded by the wire limit: %v", err)
	}
}

func gzipBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestSyncBodyDecodedLimit(t *testing.T) {
	encoded := gzipBytes(t, bytes.Repeat([]byte{'a'}, 5000))
	if got, err := decodeSyncBody(bytes.NewReader(encoded), "gzip", 1<<20, 5000); err != nil || len(got) != 5000 {
		t.Fatalf("exactly at the decoded limit: %d, %v", len(got), err)
	}
	if _, err := decodeSyncBody(bytes.NewReader(encoded), "gzip", 1<<20, 4999); !errors.Is(err, ErrSyncDecodedTooLarge) {
		t.Fatalf("one byte over the decoded limit: %v", err)
	}
	if _, err := EncodeSyncBody(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := encodeSyncBody(make([]byte, 11), 1<<20, 10); !errors.Is(err, ErrSyncDecodedTooLarge) {
		t.Fatalf("encoding a body over the decoded limit: %v", err)
	}
}

func TestSyncBodyWireLimit(t *testing.T) {
	// Incompressible input, so the compressed size is about the input size.
	noise := make([]byte, 4096)
	state := uint32(1)
	for i := range noise {
		state = state*1664525 + 1013904223
		noise[i] = byte(state >> 24)
	}
	encoded := gzipBytes(t, noise)
	limit := int64(len(encoded))
	if got, err := decodeSyncBody(bytes.NewReader(encoded), "gzip", limit, 1<<20); err != nil || !bytes.Equal(got, noise) {
		t.Fatalf("exactly at the wire limit: %v", err)
	}
	if _, err := decodeSyncBody(bytes.NewReader(encoded), "gzip", limit-1, 1<<20); !errors.Is(err, ErrSyncWireTooLarge) {
		t.Fatalf("one byte over the wire limit: %v", err)
	}
	// Bytes after the stream count against the wire limit too.
	trailing := append(append([]byte{}, encoded...), bytes.Repeat([]byte{0}, 100)...)
	if _, err := decodeSyncBody(bytes.NewReader(trailing), "gzip", limit+10, 1<<20); err == nil {
		t.Fatal("trailing bytes past the wire limit accepted")
	}
	if _, err := encodeSyncBody(noise, limit-1, 1<<20); !errors.Is(err, ErrSyncWireTooLarge) {
		t.Fatalf("encoding past the wire limit: %v", err)
	}
}

func TestSyncBodyRefusesWhatItCannotRead(t *testing.T) {
	good := gzipBytes(t, []byte(`{"a":1}`))
	for name, tc := range map[string]struct {
		encoding string
		body     []byte
		unknown  bool
	}{
		"deflate":        {"deflate", good, true},
		"br":             {"br", good, true},
		"zstd":           {"zstd", good, true},
		"two codings":    {"gzip, gzip", good, true},
		"with parameter": {"gzip;q=1", good, true},
		"x-gzip":         {"x-gzip", good, true},
		"not gzip":       {"gzip", []byte(`{"a":1}`), false},
		"truncated":      {"gzip", good[:len(good)-4], false},
		"empty":          {"gzip", nil, false},
		"trailing junk":  {"gzip", append(append([]byte{}, good...), "junk"...), false},
		"corrupt crc":    {"gzip", append(append([]byte{}, good[:len(good)-8]...), make([]byte, 8)...), false},
	} {
		_, err := DecodeSyncBody(bytes.NewReader(tc.body), tc.encoding)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if tc.unknown && !errors.Is(err, ErrSyncUnknownEncoding) {
			t.Errorf("%s: %v is not ErrSyncUnknownEncoding", name, err)
		}
	}
	// An unknown encoding is refused before anything is read.
	if _, err := DecodeSyncBody(failingReader{}, "br"); !errors.Is(err, ErrSyncUnknownEncoding) {
		t.Fatalf("unknown encoding read the body: %v", err)
	}
	if _, err := DecodeSyncBody(failingReader{}, "gzip"); err == nil {
		t.Fatal("a failing reader was accepted")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// A bomb is 64 MiB of zeros in about 64 KiB. With a 1 MiB decoded limit the
// decoder must stop after the limit and must not allocate anything near the
// bomb's size.
func TestSyncBodyBombIsRefusedWithoutAllocatingItsSize(t *testing.T) {
	const bombSize, limit = 64 << 20, 1 << 20
	var out bytes.Buffer
	w, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(w, zeros{}, bombSize); err != nil {
		t.Fatal(err)
	}
	w.Close()
	bomb := out.Bytes()
	if len(bomb) > 1<<20 {
		t.Fatalf("test bomb is not a bomb: %d bytes", len(bomb))
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err = decodeSyncBody(bytes.NewReader(bomb), "gzip", MaxSyncWireBytes, limit)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrSyncDecodedTooLarge) {
		t.Fatalf("bomb: %v", err)
	}
	// The limit plus the buffer's growth step and the inflater's own state;
	// the bomb is 32 times the limit.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8*limit {
		t.Fatalf("decoding a %d byte bomb with a %d byte limit allocated %d bytes", bombSize, limit, allocated)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestAcceptsSyncGzip(t *testing.T) {
	for header, want := range map[string]bool{
		"": false, "gzip": true, "GZIP": true, "br, gzip": true, "gzip;q=0.5": true,
		"gzip;q=0": false, "gzip; q=0.0": false, "identity": false, "br": false, "*": false,
		"x-gzip": false, "gzip, br;q=0": true, "gzip;q=0.": false, "gzip;q=0.000": false,
		"gzip;q=0.001": true, "gzip;q=abc": false, "gzip;q=NaN": false, "gzip;q=inf": false, "gzip;q=+Inf": false, "gzip;q=1.5": false, "gzip;q=2": false, "gzip;q=1.0": true, "gzip ; Q=0": false,
	} {
		if got := AcceptsSyncGzip(header); got != want {
			t.Errorf("AcceptsSyncGzip(%q) = %v, want %v", header, got, want)
		}
	}
}

func TestSyncEncodingFromHeaders(t *testing.T) {
	for values, want := range map[string]string{"": "identity", "gzip": "gzip", "identity": "identity"} {
		var headers []string
		if values != "" {
			headers = []string{values}
		}
		if got, err := SyncEncodingFromHeaders(headers); err != nil || got != want {
			t.Errorf("%q = %q, %v", values, got, err)
		}
	}
	for _, headers := range [][]string{{"gzip", "gzip"}, {"gzip", "identity"}, {"", ""}, {"gzip, gzip"}, {"br"}} {
		if _, err := SyncEncodingFromHeaders(headers); !errors.Is(err, ErrSyncUnknownEncoding) {
			t.Errorf("%q accepted: %v", headers, err)
		}
	}
}

func TestSyncCompressionStateMachine(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	c := NewSyncCompression(true, func() time.Time { return clock })
	if c.RequestEncoding() != "" {
		t.Fatal("the first request is not plain")
	}
	c.ObserveResponse(200, "gzip")
	if c.RequestEncoding() != "gzip" {
		t.Fatal("an advertised gzip did not switch it on")
	}
	// Only a 2xx changes the state: errors and dropped connections say nothing.
	for _, status := range []int{500, 502, 503, 429, 401, 304, 400, 415} {
		c.ObserveResponse(status, "")
		if c.RequestEncoding() != "gzip" {
			t.Fatalf("a %d without the header switched it off", status)
		}
	}
	// A 2xx REPLACES the state: absent means plain.
	c.ObserveResponse(204, "")
	if c.RequestEncoding() != "" {
		t.Fatal("an absent header on a 2xx did not switch it off")
	}
	c.ObserveResponse(200, "gzip")
	c.ObserveResponse(503, "identity")
	if c.RequestEncoding() != "gzip" {
		t.Fatal("a 5xx changed the state")
	}

	// A refusal of the coding: one plain retry, then off for an hour, then on
	// again on what was last learned.
	for _, status := range []int{400, 401, 403, 404, 406, 411, 413, 415, 501} {
		c.ObserveResponse(200, "gzip")
		if !c.Rejected(status, "gzip") || c.RequestEncoding() != "" {
			t.Fatalf("a %d to a gzip request did not fall back to plain", status)
		}
		c.ObserveResponse(200, "gzip") // the retry's own 2xx advertises gzip
		if c.RequestEncoding() != "" {
			t.Fatal("an advertisement during the cooldown switched it on")
		}
		clock = clock.Add(SyncGzipCooldown - time.Second)
		c.ObserveResponse(200, "gzip")
		if c.RequestEncoding() != "" {
			t.Fatal("it came back before the cooldown ended")
		}
		clock = clock.Add(2 * time.Second)
		if c.RequestEncoding() != "gzip" {
			t.Fatal("the end of the cooldown did not try gzip again on what was learned")
		}
	}
	// No 2xx needed to come back: an agent whose plain reports keep failing
	// (a body over a proxy's plain limit) is not stranded plain.
	c.ObserveResponse(200, "gzip")
	if !c.Rejected(403, "gzip") {
		t.Fatal("a 403 to a gzip request was not a refusal")
	}
	for i := 0; i < 48; i++ {
		clock = clock.Add(time.Hour)
		c.ObserveResponse(413, "") // the plain reports keep failing
	}
	if c.RequestEncoding() != "gzip" {
		t.Fatal("an agent with no 2xx since a refusal stayed plain after the cooldown")
	}
	// A 2xx after the cooldown still replaces the state: a panel that stopped
	// advertising gets plain requests.
	c.ObserveResponse(200, "")
	if c.RequestEncoding() != "" {
		t.Fatal("a 2xx without the header after the cooldown did not switch it off")
	}
	c.ObserveResponse(200, "gzip")
	for _, tc := range []struct {
		status int
		sent   string
	}{{400, ""}, {415, ""}, {403, ""}, {500, "gzip"}, {502, "gzip"}, {503, "gzip"}, {504, "gzip"}, {429, "gzip"},
		{520, "gzip"}, {522, "gzip"}, {530, "gzip"}, {200, "gzip"}, {204, "gzip"}} {
		if c.Rejected(tc.status, tc.sent) {
			t.Errorf("status %d for %q treated as a rejection", tc.status, tc.sent)
		}
	}
	if c.RequestEncoding() != "gzip" {
		t.Fatal("an unrelated status switched compression off")
	}
	// Never on without the declaration.
	undeclared := NewSyncCompression(false, nil)
	undeclared.ObserveResponse(200, "gzip")
	if undeclared.RequestEncoding() != "" {
		t.Fatal("compressed without declaring the capability")
	}
}

// Decoding a body of N bytes holds the chunks and the result, so allocates
// about 2N in all; a doubling buffer allocated about 4N here (32 MiB for 8 MiB).
func TestSyncBodyDecodePeakIsBounded(t *testing.T) {
	const size = 8 << 20
	encoded := gzipBytes(t, bytes.Repeat([]byte("0123456789abcdef"), size/16))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	got, err := decodeSyncBody(bytes.NewReader(encoded), "gzip", MaxSyncWireBytes, 2*size)
	runtime.ReadMemStats(&after)
	if err != nil || len(got) != size {
		t.Fatalf("decode: %d, %v", len(got), err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 2*size+size/4 {
		t.Fatalf("decoding %d bytes allocated %d", size, allocated)
	}
}
