package cli

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/telemetry"
)

// divergenceDoc is a file of --divergence-dir.
type divergenceDoc struct {
	Metadata struct {
		Generated time.Time      `json:"generated"`
		Reason    string         `json:"reason"`
		Cache     string         `json:"cache"`
		Episode   int            `json:"episode"`
		StartedAt *time.Time     `json:"started_at"`
		Compared  []string       `json:"compared"`
		SettleNS  int64          `json:"settle_ns"`
		Counts    map[string]int `json:"counts"`
		Settling  map[string]int `json:"settling"`
		Items     int            `json:"items"`
	} `json:"metadata"`
	Items []map[string]any `json:"items"`
}

// runCompareFiles is runCompare with --divergence-dir: it returns the run
// and a function that stops it, waits for the files and returns them by
// name.
func runCompareFiles(t *testing.T, srvs []*rtrtest.Server, detector *telemetry.Detector) (*compareRun, func() map[string]divergenceDoc) {
	t.Helper()
	dir := t.TempDir()
	files, err := newDivergenceFiles(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(files.close)
	r := runCompareWith(t, srvs, testSettle, detector, func(set *monitorSet) { set.cmp.OnList(files.accept) })
	return r, func() map[string]divergenceDoc {
		t.Helper()
		r.stop()
		files.close()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]divergenceDoc{}
		for _, e := range entries {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			var doc divergenceDoc
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("%s is not JSON: %v\n%s", e.Name(), err, raw)
			}
			if doc.Metadata.Items != len(doc.Items) {
				t.Errorf("%s: metadata says %d items, the list has %d", e.Name(), doc.Metadata.Items, len(doc.Items))
			}
			if info, err := e.Info(); err != nil || info.Mode().Perm() != 0o644 {
				t.Errorf("%s: mode %v (%v), want 0644", e.Name(), info.Mode().Perm(), err)
			}
			out[e.Name()] = doc
		}
		return out
	}
}

// the file names of one reason
func named(files map[string]divergenceDoc, reason string) []string {
	var out []string
	for name := range files {
		if strings.HasSuffix(name, "-"+reason+".json") {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// A cache missing more VRPs than a divergence record has samples for: the
// record names the file that lists them all, and the file has every one of
// them, with a difference that had not settled yet marked as such.
func TestDivergenceFileWhenEpisodeOpens(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	setAll(s, baseVRPs, nil)
	r, stop := runCompareFiles(t, s, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))

	many := rtrtest.GenVRPs(5000, 30, 65002)
	r.advance(t, a, rtrtest.Delta{AnnounceVRPs: many})
	r.advance(t, b, rtrtest.Delta{AnnounceVRPs: many})
	outlast()
	// C's own sync opens its episode, and brings a VRP nobody else has.
	r.advance(t, c, rtrtest.Delta{AnnounceVRPs: rtrtest.GenVRPs(9000, 1, 65003)})
	divs := r.waitRecords(t, "divergence", 1)
	files := stop()

	dv := divs[0]
	name, _ := dv["items_file"].(string)
	if name == "" || name != filepath.Base(name) || !strings.HasSuffix(name, "-divergence.json") {
		t.Fatalf("items_file %q, want a file name ending in -divergence.json; record %v", name, dv)
	}
	if strings.ContainsAny(strings.TrimSuffix(name, ".json"), ":[]/") {
		t.Errorf("items_file %q has characters of the cache's address that do not belong in a file name", name)
	}
	doc, ok := files[name]
	if !ok {
		t.Fatalf("no file %s in the directory, which has %v", name, named(files, "divergence"))
	}
	if len(files) != 1 {
		t.Errorf("%d files, want the one of the episode", len(files))
	}

	md := doc.Metadata
	if md.Reason != "divergence" || md.Cache != c.Addr() || md.Episode != 1 || md.StartedAt == nil ||
		!slices.Equal(md.Compared, addrs(a, b, c)) || md.SettleNS != int64(testSettle) {
		t.Errorf("metadata %+v, want divergence at %s, episode 1, all three compared, settle %d", md, c.Addr(), testSettle)
	}
	if started, _ := dv["started_at"].(string); md.StartedAt != nil && md.StartedAt.Format(time.RFC3339Nano) != started {
		t.Errorf("started_at %v in the file, %s in the record", md.StartedAt, started)
	}
	if !reflect.DeepEqual(md.Counts, map[string]int{"vrp_missing": 30}) || !reflect.DeepEqual(md.Settling, map[string]int{"vrp_extra": 1}) {
		t.Errorf("counts %v settling %v, want 30 vrp_missing settled and 1 vrp_extra settling", md.Counts, md.Settling)
	}
	if !reflect.DeepEqual(counts(dv), map[string]float64{"vrp_missing": 30}) {
		t.Errorf("record counts %v, want vrp_missing 30", dv["counts"])
	}
	if len(doc.Items) != 31 {
		t.Fatalf("%d items, want 31", len(doc.Items))
	}

	// The record's samples are the first of the file's settled items, in
	// the sample format: the file adds first_seen and settled.
	samples := dv["samples"].([]any)
	if len(samples) != 20 {
		t.Fatalf("%d samples in the record, want 20", len(samples))
	}
	for i, it := range doc.Items[:30] {
		if it["kind"] != "vrp_missing" || it["settled"] != true || it["asn"] != 65002.0 ||
			!slices.Equal(strs(it["agree"]), addrs(c)) || !slices.Equal(strs(it["disagree"]), addrs(a, b)) {
			t.Fatalf("item %d: %v, want a settled vrp_missing of AS65002 at C against A and B", i, it)
		}
		if _, err := time.Parse(time.RFC3339Nano, it["first_seen"].(string)); err != nil {
			t.Fatalf("item %d: first_seen %v: %v", i, it["first_seen"], err)
		}
		if i < len(samples) {
			want := maps(it, "first_seen", "settled")
			if !reflect.DeepEqual(samples[i], any(want)) {
				t.Fatalf("sample %d of the record is %v, item %d of the file %v", i, samples[i], i, want)
			}
		}
	}
	if last := doc.Items[30]; last["kind"] != "vrp_extra" || last["settled"] != false || last["asn"] != 65003.0 {
		t.Errorf("last item %v, want the VRP only C has, as vrp_extra still settling", last)
	}
}

// maps returns a copy of m without the given keys.
func maps(m map[string]any, without ...string) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		if !slices.Contains(without, k) {
			out[k] = v
		}
	}
	return out
}

// A list asked for on demand (SIGUSR1): one file for every compared cache,
// with what it disagrees on now, settled or not, and with no items for a
// cache that agrees with the others.
func TestDivergenceFileOnDemand(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	setAll(s, baseVRPs, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501, 64502}}})
	r, stop := runCompareFiles(t, s, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))

	r.advance(t, c, rtrtest.Delta{AnnounceASPAs: []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501}}}})
	r.waitTracked(t, c, telemetry.DivergenceASPAMismatch, 1)
	if n := r.set.cmp.ListAll(telemetry.ListOnSignal); n != 3 {
		t.Fatalf("ListAll made %d lists, want one for each of the 3 caches", n)
	}
	files := stop()

	names := named(files, "signal")
	if len(names) != 3 || len(files) != 3 {
		t.Fatalf("files %v, want three -signal.json files and nothing else", files)
	}
	for _, name := range names {
		doc := files[name]
		md := doc.Metadata
		if md.Reason != "signal" || md.Episode != 0 || md.StartedAt != nil {
			t.Errorf("%s: metadata %+v, want reason signal and no episode", name, md)
		}
		if md.Cache != c.Addr() {
			if len(doc.Items) != 0 || len(md.Counts) != 0 || len(md.Settling) != 0 {
				t.Errorf("%s: %d items for a cache in the majority, want none", name, len(doc.Items))
			}
			continue
		}
		if len(doc.Items) != 1 || !reflect.DeepEqual(md.Settling, map[string]int{"aspa_mismatch": 1}) || len(md.Counts) != 0 {
			t.Fatalf("%s: items %v settling %v counts %v, want one aspa_mismatch still settling", name, doc.Items, md.Settling, md.Counts)
		}
		it := doc.Items[0]
		if it["kind"] != "aspa_mismatch" || it["customer_asn"] != 64500.0 || it["settled"] != false ||
			!reflect.DeepEqual(it["providers"], []any{64501.0}) || !reflect.DeepEqual(it["majority_providers"], []any{64501.0, 64502.0}) ||
			!slices.Equal(strs(it["agree"]), addrs(c)) || !slices.Equal(strs(it["disagree"]), addrs(a, b)) {
			t.Errorf("%s: item %v, want AS64500 with providers [64501] against the majority's [64501 64502]", name, it)
		}
	}
	if len(r.records(t, "divergence")) != 0 {
		t.Errorf("a divergence record for a difference that had not settled; NDJSON:\n%s", r.ndjson)
	}
}

// A cache that returns to data it served earlier: the file lists what it
// then disagrees with the others on, as of that sync, though none of it
// has settled and no divergence record exists yet.
func TestDivergenceFileOnDataRegressed(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	setAll(s, baseVRPs, nil)
	d := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	d.Data().SetThreshold(300 * time.Millisecond)
	r, stop := runCompareFiles(t, s, d)

	time.Sleep(400 * time.Millisecond) // the first set is current for longer than the threshold
	for _, srv := range s {
		r.advance(t, srv, rtrtest.Delta{AnnounceVRPs: extraVRPs})
	}
	r.advance(t, a, rtrtest.Delta{WithdrawVRPs: extraVRPs}) // A is back to the first set
	regs := r.waitRecords(t, "data_regressed", 1)
	if regs[0]["cache"] != a.Addr() {
		t.Fatalf("data_regressed %v, want one at %s", regs[0], a.Addr())
	}
	// The list waits for A's side of the comparison to hold that sync.
	deadline := time.Now().Add(5 * time.Second)
	for r.set.cmp.Tracked()[a.Addr()][telemetry.DivergenceVRPMissing] != 5 {
		if time.Now().After(deadline) {
			t.Fatalf("A: tracked %v, want 5 vrp_missing", r.set.cmp.Tracked()[a.Addr()])
		}
		time.Sleep(5 * time.Millisecond)
	}
	files := stop()

	names := named(files, "data_regressed")
	if len(names) != 1 {
		t.Fatalf("files %v, want one -data_regressed.json", files)
	}
	doc := files[names[0]]
	md := doc.Metadata
	if md.Reason != "data_regressed" || md.Cache != a.Addr() || !slices.Equal(md.Compared, addrs(a, b, c)) {
		t.Errorf("metadata %+v, want data_regressed at %s", md, a.Addr())
	}
	if len(doc.Items) != 5 || !reflect.DeepEqual(md.Settling, map[string]int{"vrp_missing": 5}) || len(md.Counts) != 0 {
		t.Fatalf("items %d settling %v counts %v, want the 5 VRPs A no longer has, still settling", len(doc.Items), md.Settling, md.Counts)
	}
	for i, it := range doc.Items {
		if it["kind"] != "vrp_missing" || it["settled"] != false || it["asn"] != 65002.0 ||
			!slices.Equal(strs(it["agree"]), addrs(a)) || !slices.Equal(strs(it["disagree"]), addrs(b, c)) {
			t.Errorf("item %d: %v, want a vrp_missing of AS65002 at A against B and C, still settling", i, it)
		}
	}
}

// A file that cannot be written (the directory is gone) is logged and
// nothing more: the monitor goes on, and the record still names the file.
func TestDivergenceFileWriteFailureIsNotFatal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lists")
	files, err := newDivergenceFiles(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	s := newCaches(t, 2, 2)
	s[0].SetData(append(slices.Clone(baseVRPs), extraVRPs...), nil)
	s[1].SetData(baseVRPs, nil)
	r := runCompareWith(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()),
		func(set *monitorSet) { set.cmp.OnList(files.accept) })
	outlast()
	r.tick(t, s[0])
	r.waitRecords(t, "divergence", 2)
	r.stop()
	files.close()
	if name := files.accept(&telemetry.DivergenceList{Cache: "x:1", Reason: "signal"}); name != "" {
		t.Errorf("a list accepted after close, as %q", name)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the directory is back: %v", err)
	}
}

func TestDivergenceFileName(t *testing.T) {
	at := time.Date(2026, 11, 28, 17, 4, 5, 999, time.FixedZone("CET", 3600))
	for cache, want := range map[string]string{
		"rtr.example.net:3323": "rtr.example.net_3323-20261128T160405Z-divergence.json",
		"[2001:db8::1]:3323":   "_2001_db8__1__3323-20261128T160405Z-divergence.json",
		"../../etc/passwd:1":   ".._.._etc_passwd_1-20261128T160405Z-divergence.json",
	} {
		got := divergenceFileName(&telemetry.DivergenceList{Cache: cache, Reason: telemetry.ListOnDivergence, Generated: at})
		if got != want || got != filepath.Base(got) {
			t.Errorf("%s: %q, want %q", cache, got, want)
		}
	}
}
