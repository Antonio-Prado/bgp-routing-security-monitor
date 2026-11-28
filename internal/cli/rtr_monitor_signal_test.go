//go:build unix

package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// #82: SIGHUP (a closed terminal, a lost SSH session, tmux kill-session)
// shuts raven rtr monitor down as SIGTERM does: the session ends with a
// disconnected (shutdown) record and the final --anomaly-snapshot is
// written. Go's default would exit at once, with neither.
//
// #80 too: the log file already holds an earlier run's records and there
// is no snapshot, so the gap history is seeded from the log at startup;
// the snapshot written at shutdown carries it.
func TestMonitorSIGHUPShutsDownCleanly(t *testing.T) {
	srv := rtrtest.NewServer(t, monitorCache(2))
	srv.SetData(rtrtest.GenVRPs(0, 3, 65001), nil)
	dir := t.TempDir()
	logFile := filepath.Join(dir, "rtr-telemetry.ndjson")
	snap := filepath.Join(dir, "anomaly-baseline.json")
	earlier, err := os.ReadFile("../telemetry/testdata/anycast-node-stall-2026-11-12.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	earlier = bytes.ReplaceAll(earlier, []byte(`"rtr.rpki.cloudflare.com:8282"`), []byte(`"`+srv.Addr()+`"`))
	if err := os.WriteFile(logFile, earlier, 0o600); err != nil {
		t.Fatal(err)
	}
	_, cold, err := telemetry.SeedBaseline(bytes.NewReader(earlier))
	if err != nil {
		t.Fatal(err)
	}

	cmd := newRTRMonitorCmd()
	cmd.SetArgs([]string{"--cache", srv.Addr(), "--log-file", logFile, "--anomaly-snapshot", snap})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	deadline := time.Now().Add(30 * time.Second)
	for {
		b, _ := os.ReadFile(logFile)
		if bytes.Contains(b[len(earlier):], []byte(`"event_type":"sync"`)) {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("monitor stopped before its first sync: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sync record within 30s; log:\n%s", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(snap); !os.IsNotExist(err) {
		t.Fatalf("snapshot before the signal: %v, want none yet", err)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("monitor after SIGHUP: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("monitor did not stop within 30s of SIGHUP")
	}

	f, err := os.Open(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var last map[string]any
	for sc := bufio.NewScanner(f); sc.Scan(); {
		last = nil
		if err := json.Unmarshal(sc.Bytes(), &last); err != nil {
			t.Fatalf("NDJSON %q: %v", sc.Text(), err)
		}
	}
	if last["event_type"] != "disconnected" || last["disconnect_reason"] != "shutdown" {
		t.Errorf("last record %v, want disconnected (shutdown)", last)
	}
	raw, err := os.ReadFile(snap)
	if err != nil {
		t.Fatalf("no anomaly snapshot after SIGHUP: %v", err)
	}
	var file struct {
		SchemaVersion int `json:"schema_version"`
		DataGaps      map[string]struct {
			Pos    int  `json:"pos"`
			Filled bool `json:"filled"`
		} `json:"data_gaps"`
	}
	if err := json.Unmarshal(raw, &file); err != nil || file.SchemaVersion != 1 {
		t.Fatalf("anomaly snapshot: %v, schema_version %d", err, file.SchemaVersion)
	}
	// The live session's first sync adds no gap: the history is the
	// seeded one.
	if g := file.DataGaps[srv.Addr()]; g.Filled || g.Pos != cold.DataGaps[0].Gaps || g.Pos == 0 {
		t.Errorf("snapshot data_gaps %+v, want the %d gaps seeded from the log", g, cold.DataGaps[0].Gaps)
	}
}

// startMonitorCmd runs "rtr monitor" with args and waits until every cache
// of srvs has a sync record in logFile. The returned channel gets the
// command's error when it ends.
func startMonitorCmd(t *testing.T, logFile string, srvs []*rtrtest.Server, args ...string) <-chan error {
	t.Helper()
	// A SIGUSR1 that found no handler would end the test binary.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGUSR1)
	t.Cleanup(func() { signal.Stop(guard) })

	cmd := newRTRMonitorCmd()
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	deadline := time.Now().Add(30 * time.Second)
	for {
		b, _ := os.ReadFile(logFile)
		synced := 0
		for _, srv := range srvs {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, `"event_type":"sync"`) && strings.Contains(line, `"cache":"`+srv.Addr()+`"`) {
					synced++
					break
				}
			}
		}
		if synced == len(srvs) {
			return done
		}
		select {
		case err := <-done:
			t.Fatalf("monitor stopped before its first syncs: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sync record of every cache within 30s; log:\n%s", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stopMonitorCmd ends the monitor with SIGTERM and waits for it.
func stopMonitorCmd(t *testing.T, done <-chan error) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("monitor after SIGTERM: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("monitor did not stop within 30s of SIGTERM")
	}
}

// SIGUSR1 with --divergence-dir: the monitor writes, for every compared
// cache, the full list of what it disagrees with the others on, and goes
// on running.
func TestMonitorSIGUSR1WritesTheDifferences(t *testing.T) {
	a, b := rtrtest.NewServer(t, monitorCache(2)), rtrtest.NewServer(t, monitorCache(2))
	a.SetData(rtrtest.GenVRPs(0, 8, 65001), nil)
	b.SetData(rtrtest.GenVRPs(0, 5, 65001), nil)
	dir := t.TempDir()
	logFile, lists := filepath.Join(dir, "rtr-telemetry.ndjson"), filepath.Join(dir, "lists")
	done := startMonitorCmd(t, logFile, []*rtrtest.Server{a, b},
		"--cache", a.Addr(), "--cache", b.Addr(), "--log-file", logFile,
		"--anomaly-snapshot", filepath.Join(dir, "anomaly-baseline.json"), "--divergence-dir", lists)

	// A sync record is written before the comparison takes the sync in:
	// signal until both caches are compared and so both have a list.
	var names []string
	deadline := time.Now().Add(30 * time.Second)
	for len(names) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("files %v within 30s of SIGUSR1, want one -signal.json for each cache", names)
		}
		if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1100 * time.Millisecond) // a file name is to the second
		names, _ = filepath.Glob(filepath.Join(lists, "*-signal.json"))
	}
	select {
	case err := <-done:
		t.Fatalf("monitor stopped at SIGUSR1: %v", err)
	default:
	}
	stopMonitorCmd(t, done)

	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Metadata struct {
				Reason   string         `json:"reason"`
				Settling map[string]int `json:"settling"`
			} `json:"metadata"`
			Items []struct {
				Kind string `json:"kind"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s is not JSON: %v\n%s", name, err, raw)
		}
		// Two caches have no majority: the 3 VRPs only A has are a split
		// at both.
		if doc.Metadata.Reason != "signal" || len(doc.Items) != 3 || doc.Items[0].Kind != "vrp_split" || doc.Metadata.Settling["vrp_split"] != 3 {
			t.Errorf("%s: %s", name, raw)
		}
	}
}

// SIGUSR1 with nothing to list is answered with a log line that says why:
// one cache, or no --divergence-dir.
func TestListOnSignalWithNothingToList(t *testing.T) {
	// A SIGUSR1 that found no handler would end the test binary.
	guard := make(chan os.Signal, 1)
	signal.Notify(guard, syscall.SIGUSR1)
	t.Cleanup(func() { signal.Stop(guard) })

	for name, tc := range map[string]struct {
		cmp  *telemetry.CrossCache
		want string
	}{
		"one cache":         {nil, "one cache is monitored"},
		"no divergence dir": {telemetry.NewCrossCache(nil, 0, nil, nil), "no --divergence-dir"},
	} {
		t.Run(name, func(t *testing.T) {
			out := &lockedBuffer{}
			sigs, stop := watchListSignals()
			defer stop()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				listOnSignal(ctx, sigs, tc.cmp, false, slog.New(slog.NewTextHandler(out, nil)))
			}()
			if err := syscall.Kill(os.Getpid(), syscall.SIGUSR1); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for !strings.Contains(out.String(), tc.want) {
				if time.Now().After(deadline) {
					t.Fatalf("no log line with %q within 5s of SIGUSR1; log: %q", tc.want, out.String())
				}
				time.Sleep(5 * time.Millisecond)
			}
			if !strings.Contains(out.String(), "nothing to list") || !strings.Contains(out.String(), "level=WARN") {
				t.Errorf("log %q, want a warning that there is nothing to list", out.String())
			}
			cancel()
			<-done
		})
	}
}
