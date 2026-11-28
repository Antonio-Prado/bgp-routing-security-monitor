package telemetry

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Write's layout: one JSON document, the metadata first, then one item a
// line in the sample format with first_seen and settled.
func TestDivergenceListWrite(t *testing.T) {
	at := time.Date(2026, 11, 28, 16, 0, 0, 0, time.UTC)
	vrp := keyOf(types.VRP{Prefix: netip.MustParsePrefix("192.0.2.0/24"), MaxLength: 24, ASN: 64500})
	l := &DivergenceList{
		Generated: at, Cache: "c:3323", Reason: ListOnDivergence, Episode: 2, StartedAt: at.Add(-time.Hour),
		Compared: []string{"a:3323", "b:3323", "c:3323"}, Settle: 20 * time.Minute,
		Counts: map[string]int{DivergenceVRPMissing: 1}, Settling: map[string]int{DivergenceASPAMismatch: 1},
		names: []string{"a:3323", "b:3323", "c:3323"},
		items: []ccItem{
			{order: kindOrder(DivergenceVRPMissing), vrp: vrp, members: 7, against: 3, first: at.Add(-time.Hour), settled: true},
			{order: kindOrder(DivergenceASPAMismatch), isASPA: true, cust: 64511, providers: []uint32{174},
				majority: []uint32{174, 3356}, members: 7, against: 3, first: at.Add(-time.Minute)},
		},
	}
	var buf bytes.Buffer
	if err := l.Write(&buf); err != nil {
		t.Fatal(err)
	}
	want := `{
  "metadata": {
    "generated": "2026-11-28T16:00:00Z",
    "reason": "divergence",
    "cache": "c:3323",
    "episode": 2,
    "started_at": "2026-11-28T15:00:00Z",
    "compared": [
      "a:3323",
      "b:3323",
      "c:3323"
    ],
    "settle_ns": 1200000000000,
    "counts": {
      "vrp_missing": 1
    },
    "settling": {
      "aspa_mismatch": 1
    },
    "items": 2
  },
  "items": [
    {"kind":"vrp_missing","prefix":"192.0.2.0/24","max_length":24,"asn":64500,"agree":["c:3323"],"disagree":["a:3323","b:3323"],"first_seen":"2026-11-28T15:00:00Z","settled":true},
    {"kind":"aspa_mismatch","customer_asn":64511,"providers":[174],"majority_providers":[174,3356],"agree":["c:3323"],"disagree":["a:3323","b:3323"],"first_seen":"2026-11-28T15:59:00Z","settled":false}
  ]
}
`
	if got := buf.String(); got != want {
		t.Errorf("Write:\n%s\nwant:\n%s", got, want)
	}
	if items := l.Items(); len(items) != 2 || items[0].Prefix != "192.0.2.0/24" || !items[0].Settled || items[1].Settled {
		t.Errorf("Items: %+v", items)
	}

	// No items, no episode: an empty list, and no episode or started_at.
	empty := &DivergenceList{Generated: at, Cache: "a:3323", Reason: ListOnSignal, Compared: []string{"a:3323", "b:3323"},
		Counts: map[string]int{}, Settling: map[string]int{}}
	buf.Reset()
	if err := empty.Write(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Metadata map[string]any `json:"metadata"`
		Items    []any          `json:"items"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if doc.Items == nil || len(doc.Items) != 0 || !strings.Contains(buf.String(), `"items": []`) {
		t.Errorf("empty list:\n%s", buf.String())
	}
	if _, ok := doc.Metadata["episode"]; ok {
		t.Errorf("episode in the metadata of a list with no episode:\n%s", buf.String())
	}
	if _, ok := doc.Metadata["started_at"]; ok {
		t.Errorf("started_at in the metadata of a list with no episode:\n%s", buf.String())
	}
}
