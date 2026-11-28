package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
)

type dumpDoc struct {
	Metadata struct {
		Cache           string `json:"cache"`
		SessionID       uint16 `json:"sessionID"`
		Serial          uint32 `json:"serial"`
		ProtocolVersion uint8  `json:"protocolVersion"`
		DataFingerprint string `json:"dataFingerprint"`
		ASPAsAvailable  bool   `json:"aspasAvailable"`
	} `json:"metadata"`
	ROAs []struct {
		ASN       string `json:"asn"`
		Prefix    string `json:"prefix"`
		MaxLength int    `json:"maxLength"`
	} `json:"roas"`
	ASPAs *[]struct {
		Customer  string   `json:"customer"`
		Providers []string `json:"providers"`
	} `json:"aspas"`
}

// runDump runs "rtr dump" with args and returns its stdout and stderr.
func runDump(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newRTRDumpCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}

func TestRTRDumpVersion2(t *testing.T) {
	cache := rtrtest.NewCache(t)
	go func() {
		q := cache.Next(5 * time.Second)
		q.Conn.Send(
			rtrtest.CacheResponse(2, 777),
			rtrtest.IPv6Prefix(2, true, netip.MustParsePrefix("2001:db8::/32"), 48, 64500),
			rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 64501),
			rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 64500),
			rtrtest.ASPA(true, 64511, 3356, 174, 0),
			rtrtest.EndOfData(2, 777, 42, 3600, 600, 7200),
		)
	}()

	out, errOut, err := runDump(t, "--cache", cache.Addr(), "--timeout", "10s")
	if err != nil {
		t.Fatalf("dump: %v\n%s", err, errOut)
	}
	var d dumpDoc
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	m := d.Metadata
	if m.Cache != cache.Addr() || m.SessionID != 777 || m.Serial != 42 || m.ProtocolVersion != 2 || !m.ASPAsAvailable {
		t.Fatalf("metadata: %+v", m)
	}
	if len(m.DataFingerprint) != 32 {
		t.Fatalf("fingerprint %q", m.DataFingerprint)
	}
	if len(d.ROAs) != 3 || d.ROAs[0].ASN != "AS64500" || d.ROAs[0].Prefix != "192.0.2.0/24" || d.ROAs[2].Prefix != "2001:db8::/32" {
		t.Fatalf("roas: %+v", d.ROAs)
	}
	if d.ASPAs == nil || len(*d.ASPAs) != 1 {
		t.Fatalf("aspas: %v", d.ASPAs)
	}
	if a := (*d.ASPAs)[0]; a.Customer != "AS64511" || strings.Join(a.Providers, ",") != "AS0,AS174,AS3356" {
		t.Fatalf("aspa: %+v", a)
	}
	if !strings.Contains(errOut, "serial 42") || !strings.Contains(errOut, "3 VRPs, 1 ASPAs") {
		t.Fatalf("summary: %q", errOut)
	}
}

// Pinned to RTR version 1 the dump says that ASPAs were unavailable and
// writes no list for them.
func TestRTRDumpVersion1(t *testing.T) {
	cache := rtrtest.NewCache(t)
	go func() {
		q := cache.Next(5 * time.Second)
		q.Conn.Send(
			rtrtest.CacheResponse(1, 5),
			rtrtest.IPv4Prefix(1, true, netip.MustParsePrefix("198.51.100.0/24"), 24, 64502),
			rtrtest.EndOfData(1, 5, 9, 3600, 600, 7200),
		)
	}()

	file := filepath.Join(t.TempDir(), "dump.json")
	_, errOut, err := runDump(t, "--cache", cache.Addr(), "--rtr-version", "1", "-o", file, "--timeout", "10s")
	if err != nil {
		t.Fatalf("dump: %v\n%s", err, errOut)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var d dumpDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	if d.Metadata.ProtocolVersion != 1 || d.Metadata.ASPAsAvailable || d.ASPAs != nil || len(d.ROAs) != 1 {
		t.Fatalf("v1 dump:\n%s", raw)
	}
	if !strings.Contains(errOut, "no ASPA in this RTR version") {
		t.Fatalf("summary: %q", errOut)
	}
}

func TestRTRDumpTimeout(t *testing.T) {
	cache := rtrtest.NewCache(t) // accepts the query and never answers
	_, _, err := runDump(t, "--cache", cache.Addr(), "--timeout", "300ms")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want a timeout, got %v", err)
	}
}

func TestRTRDumpBadTransport(t *testing.T) {
	if _, _, err := runDump(t, "--transport", "udp"); err == nil {
		t.Fatal("want an error for --transport udp")
	}
}

// A cache that refuses the connection ends the dump at once with the dial's
// error, not after --timeout with a timeout.
func TestRTRDumpUnreachable(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close() // nothing listens there now: connection refused

	start := time.Now()
	_, _, err = runDump(t, "--cache", addr, "--timeout", "20s")
	if err == nil || !strings.Contains(err.Error(), "cannot reach "+addr) || strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want the dial error, got %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %s: it waited for the timeout", d)
	}
}

// While the first sync is under way the dump says that the session is open
// and, every progressEvery, how many records it has received.
func TestRTRDumpProgress(t *testing.T) {
	old := progressEvery
	progressEvery = 50 * time.Millisecond
	t.Cleanup(func() { progressEvery = old })

	cache := rtrtest.NewCache(t)
	go func() {
		q := cache.Next(5 * time.Second)
		q.Conn.Send(
			rtrtest.CacheResponse(2, 9),
			rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 64500),
			rtrtest.ASPA(true, 64511, 174),
		)
		time.Sleep(300 * time.Millisecond) // a slow transfer
		q.Conn.Send(rtrtest.EndOfData(2, 9, 1, 3600, 600, 7200))
	}()

	_, errOut, err := runDump(t, "--cache", cache.Addr(), "--timeout", "10s")
	if err != nil {
		t.Fatalf("dump: %v\n%s", err, errOut)
	}
	if !strings.Contains(errOut, "session open at RTR version 2") || !strings.Contains(errOut, "2 records received so far") {
		t.Fatalf("progress: %q", errOut)
	}
}

// A cache that is still building its data answers every query with No Data
// Available. Until a session opens the dump prints no count of records, and
// each of those sessions gets a line with why it ended.
func TestRTRDumpCacheNotReady(t *testing.T) {
	old := progressEvery
	progressEvery = 20 * time.Millisecond
	t.Cleanup(func() { progressEvery = old })

	cache := rtrtest.NewCache(t)
	go func() {
		for range 2 {
			q := cache.Next(5 * time.Second)
			q.Conn.Send(rtrtest.ErrorReport(2, 2, "Running initial validation"))
		}
		q := cache.Next(5 * time.Second)
		q.Conn.Send(
			rtrtest.CacheResponse(2, 9),
			rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 64500),
		)
		time.Sleep(200 * time.Millisecond) // a slow transfer
		q.Conn.Send(rtrtest.EndOfData(2, 9, 1, 3600, 600, 7200))
	}()

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	vrps, aspas := store.NewVRPStore(), store.NewASPAStore()
	client, err := newMonitorClientStores(cache.Addr(), "tcp", "auto", vrps, aspas, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	// Several ticks of progressEvery pass between two sessions.
	client.SetReconnectBackoff(150*time.Millisecond, 150*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var progress bytes.Buffer
	snap, err := takeRTRSnapshot(ctx, client, cache.Addr(), vrps, aspas, time.Now, &progress)
	if err != nil {
		t.Fatalf("dump: %v\n%s", err, progress.String())
	}
	if len(snap.vrps) != 1 {
		t.Fatalf("got %d VRPs, want 1", len(snap.vrps))
	}

	out := progress.String()
	ended := cache.Addr() + ": session ended before End of Data: cache has no data available yet (Running initial validation); trying again\n"
	if n := strings.Count(out, ended); n != 2 {
		t.Fatalf("want the reason of both sessions that ended early, got %d:\n%s", n, out)
	}
	opened := strings.Index(out, "session open at RTR version 2")
	if opened < 0 {
		t.Fatalf("no line for the session that opened:\n%s", out)
	}
	if strings.Contains(out[:opened], "records received so far") {
		t.Fatalf("a count of records before any session opened:\n%s", out)
	}
	if !strings.Contains(out[opened:], "1 records received so far") {
		t.Fatalf("no count of records while the session was open:\n%s", out)
	}
}

// A session that ends early for any other reason is on stderr already: the
// client logs it as an error, with what ended it, and the dump adds no line
// of its own.
func TestRTRDumpDroppedSessionIsLoggedOnce(t *testing.T) {
	cache := rtrtest.NewCache(t)
	go func() {
		q := cache.Next(5 * time.Second)
		q.Conn.Send(
			rtrtest.CacheResponse(2, 9),
			rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 64500),
		)
		q.Conn.Close() // dropped in the middle of the transfer
		q = cache.Next(5 * time.Second)
		q.Conn.Send(
			rtrtest.CacheResponse(2, 9),
			rtrtest.IPv4Prefix(2, true, netip.MustParsePrefix("192.0.2.0/24"), 24, 64500),
			rtrtest.EndOfData(2, 9, 1, 3600, 600, 7200),
		)
	}()

	// Standard error as the command sets it up: the client's log from the
	// warning level, and the dump's own lines.
	stderr := &lockedBuffer{}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	vrps, aspas := store.NewVRPStore(), store.NewASPAStore()
	client, err := newMonitorClientStores(cache.Addr(), "tcp", "auto", vrps, aspas, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	client.SetReconnectBackoff(50*time.Millisecond, 50*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := takeRTRSnapshot(ctx, client, cache.Addr(), vrps, aspas, time.Now, stderr); err != nil {
		t.Fatalf("dump: %v\n%s", err, stderr.String())
	}

	out := stderr.String()
	if n := strings.Count(out, `level=ERROR msg="RTR session failed, reconnecting"`); n != 1 {
		t.Fatalf("want the client's error line for the dropped session once, got %d:\n%s", n, out)
	}
	if strings.Contains(out, "session ended before End of Data") {
		t.Fatalf("the dump repeated what the client had logged:\n%s", out)
	}
	if n := strings.Count(out, "session open at RTR version 2"); n != 2 {
		t.Fatalf("want a line for each of the two sessions that opened, got %d:\n%s", n, out)
	}
}
