package telemetry

import (
	"bufio"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/dump"
)

// The full list of a cache's differences.
//
// A divergence record names at most maxSamples of the items a cache
// disagrees on, and is written once per episode. A DivergenceList holds all
// of them as of one moment, settled or still settling, for a file beside
// the NDJSON stream: the stream stays one short line a record whatever the
// size of the incident. The comparison makes one when a divergence episode
// opens, when a cache returns to earlier data (ListAtSync) and on demand
// (ListAll), and hands it to the function set with OnList.

// Why a DivergenceList was made: its Reason.
const (
	ListOnDivergence    = "divergence"
	ListOnDataRegressed = "data_regressed"
	ListOnSignal        = "signal"
)

// ccItem is one difference attributed to a cache, in the comparison's own
// terms: about 150 bytes, with no string in it, where a sample holds its
// prefix and the names of the caches. A list of a few hundred thousand of
// them is made with the comparison locked, and turned into samples only as
// it is written.
type ccItem struct {
	order               int // the kind, as an index of DivergenceKinds
	isASPA              bool
	vrp                 vrpKey
	cust                uint32
	providers, majority []uint32
	members             uint64 // the caches compared on the item
	against             uint64 // those of them that do not hold what the cache holds
	first               time.Time
	settled             bool
}

// differencesLocked returns every difference attributed to m, sorted by
// kind and then by item. settled says which have kept their shape for
// longer than settle: the ones a divergence record counts.
func (c *CrossCache) differencesLocked(m *CrossCacheMember, all uint64, settle time.Duration, now time.Time) []ccItem {
	var items []ccItem
	for k, d := range c.vrpDiffs {
		mask, kind := d.attribution()
		if mask&m.bit == 0 {
			continue
		}
		same := d.holders
		if d.holders&m.bit == 0 {
			same = all &^ d.holders
		}
		items = append(items, ccItem{
			order: kindOrder(kind), vrp: k, members: all, against: all &^ same,
			first: d.first, settled: now.Sub(d.first) > settle,
		})
	}
	for cust, d := range c.aspaDiffs {
		for _, a := range d.attribution() {
			if a.mask&m.bit == 0 {
				continue
			}
			var same uint64
			for _, g := range d.groups {
				if g.mask&m.bit != 0 {
					same = g.mask
				}
			}
			it := ccItem{
				order: kindOrder(a.kind), isASPA: true, cust: cust, members: d.members, against: d.members &^ same,
				first: d.first, settled: now.Sub(d.first) > settle, providers: slices.Clone(m.aspas[cust]),
			}
			if maj := d.majority(); maj >= 0 && len(d.groups[maj].providers) > 0 {
				it.majority = slices.Clone(d.groups[maj].providers)
			}
			items = append(items, it)
		}
	}
	slices.SortFunc(items, func(a, b ccItem) int {
		if a.order != b.order {
			return cmp.Compare(a.order, b.order)
		}
		if a.isASPA {
			return cmp.Compare(a.cust, b.cust)
		}
		return compareVRPKeys(a.vrp, b.vrp)
	})
	return items
}

// sample is the item as a divergence record's sample. names gives the
// caches of a mask.
func (it *ccItem) sample(names func(uint64) []string) DivergenceSample {
	s := DivergenceSample{Kind: DivergenceKinds[it.order]}
	if it.isASPA {
		cust := it.cust
		s.CustomerASN, s.Providers, s.MajorityProviders = &cust, it.providers, it.majority
	} else {
		maxLen, asn := it.vrp.maxLen, it.vrp.asn
		s.Prefix, s.MaxLength, s.ASN = it.vrp.prefix().String(), &maxLen, &asn
	}
	s.Agree, s.Disagree = names(it.members&^it.against), names(it.against)
	return s
}

// DivergenceItem is one item of a DivergenceList: a divergence record's
// sample, with when the difference took its present shape and whether it
// has settled.
type DivergenceItem struct {
	DivergenceSample
	// FirstSeen is when the difference was first seen in its present shape
	// (the caches compared, and which of them hold what).
	FirstSeen time.Time `json:"first_seen"`
	// Settled says that the difference has lasted longer than the settle
	// window: it is one of those a divergence record counts.
	Settled bool `json:"settled"`
}

// DivergenceList is every difference attributed to one cache at one moment.
type DivergenceList struct {
	Generated time.Time
	Cache     string
	// Reason is why the list was made: ListOnDivergence, ListOnDataRegressed
	// or ListOnSignal.
	Reason string
	// Episode and StartedAt are those of the cache's open divergence
	// episode; Episode is 0 when it has none.
	Episode   int
	StartedAt time.Time
	Compared  []string
	Settle    time.Duration
	// Counts are the settled differences by kind, as a divergence record's
	// counts; Settling are those still inside the settle window.
	Counts, Settling map[string]int

	names []string // every cache of the comparison, by bit
	items []ccItem
}

// listLocked makes the list of m's differences as of now, or returns nil
// when m is not compared with any other cache. items, if not nil, are m's
// differences already worked out for the same now and settle.
func (c *CrossCache) listLocked(m *CrossCacheMember, reason string, items []ccItem) *DivergenceList {
	members, all, v2 := c.comparedLocked()
	if !m.inSession || len(members) < 2 {
		return nil
	}
	now := c.now()
	settle := c.settleLocked(members)
	if items == nil {
		c.diffLocked(members, all, v2, now)
		items = c.differencesLocked(m, all, settle, now)
	}
	l := &DivergenceList{
		Generated: now.UTC(), Cache: m.name, Reason: reason, Compared: c.names(all), Settle: settle,
		Counts: map[string]int{}, Settling: map[string]int{}, items: items,
	}
	if m.episode != nil {
		l.Episode, l.StartedAt = m.episode.n, m.episode.started.UTC()
	}
	for _, o := range c.members {
		l.names = append(l.names, o.name)
	}
	for i := range items {
		kind := DivergenceKinds[items[i].order]
		if items[i].settled {
			l.Counts[kind]++
		} else {
			l.Settling[kind]++
		}
	}
	return l
}

// Len is the number of items.
func (l *DivergenceList) Len() int { return len(l.items) }

// namer returns the caches of a mask, keeping each answer: a list has a few
// distinct masks and may have very many items.
func (l *DivergenceList) namer() func(uint64) []string {
	seen := map[uint64][]string{}
	return func(mask uint64) []string {
		if out, ok := seen[mask]; ok {
			return out
		}
		out := []string{}
		for i, name := range l.names {
			if mask&(1<<i) != 0 {
				out = append(out, name)
			}
		}
		seen[mask] = out
		return out
	}
}

func (l *DivergenceList) item(i int, names func(uint64) []string) DivergenceItem {
	it := &l.items[i]
	return DivergenceItem{DivergenceSample: it.sample(names), FirstSeen: it.first.UTC(), Settled: it.settled}
}

// Items returns the items, sorted by kind and then by item.
func (l *DivergenceList) Items() []DivergenceItem {
	names := l.namer()
	out := make([]DivergenceItem, len(l.items))
	for i := range l.items {
		out[i] = l.item(i, names)
	}
	return out
}

// listMetadata is the "metadata" member of a list as Write writes it.
type listMetadata struct {
	Generated time.Time      `json:"generated"`
	Reason    string         `json:"reason"`
	Cache     string         `json:"cache"`
	Episode   int            `json:"episode,omitempty"`
	StartedAt *time.Time     `json:"started_at,omitempty"`
	Compared  []string       `json:"compared"`
	SettleNS  time.Duration  `json:"settle_ns"`
	Counts    map[string]int `json:"counts"`
	Settling  map[string]int `json:"settling"`
	Items     int            `json:"items"`
}

// Write writes the list as one JSON document: a "metadata" object, then
// "items", one item a line, each a divergence record's sample with
// first_seen and settled. The metadata's "items" is their number, so that a
// reader can tell a whole file from a cut one.
func (l *DivergenceList) Write(w io.Writer) error {
	md := listMetadata{
		Generated: l.Generated, Reason: l.Reason, Cache: l.Cache, Episode: l.Episode, Compared: l.Compared,
		SettleNS: l.Settle, Counts: l.Counts, Settling: l.Settling, Items: len(l.items),
	}
	if l.Episode != 0 {
		md.StartedAt = &l.StartedAt
	}
	head, err := json.MarshalIndent(md, "  ", "  ")
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(w, 1<<20)
	fmt.Fprintf(bw, "{\n  \"metadata\": %s,\n", head)
	names := l.namer()
	dump.WriteList(bw, "items", len(l.items), true, func(i int) string {
		line, merr := json.Marshal(l.item(i, names))
		if merr != nil && err == nil {
			err = merr
		}
		return string(line)
	})
	fmt.Fprintf(bw, "}\n")
	if ferr := bw.Flush(); ferr != nil {
		return ferr
	}
	return err
}

// OnList sets fn to be handed every list of differences the comparison
// makes: one for a cache when its divergence episode opens, and those asked
// for with ListAtSync and ListAll. fn returns the name of the file the list
// goes to, which the divergence record carries as items_file, or "" when
// it goes nowhere. It runs with the comparison locked, on an RTR client's
// goroutine or the caller's of ListAtSync and ListAll: it must not block,
// and so not write the file itself. Without fn no list is made. Call
// before any client starts.
func (c *CrossCache) OnList(fn func(*DivergenceList) string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.list = fn
}

// ListAll makes the list of every compared cache's differences as of now,
// one a cache, a cache with none included, and returns how many it made: 0
// when fewer than two caches are compared, or without OnList.
func (c *CrossCache) ListAll(reason string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.list == nil {
		return 0
	}
	n := 0
	for _, m := range c.members {
		if l := c.listLocked(m, reason, nil); l != nil {
			c.list(l)
			n++
		}
	}
	return n
}

// ListAtSync makes the list of cache's differences as of the sync whose
// record carries fingerprint (its data_fingerprint): now when the cache's
// side of the comparison already holds that data, else when its sync
// callback runs. A sync's record is written before the client's update and
// sync callbacks run, so whoever reads the record may be ahead of the
// comparison.
func (c *CrossCache) ListAtSync(cache, reason, fingerprint string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := c.byName[cache]
	if m == nil || c.list == nil {
		return
	}
	if fingerprint == "" || m.fingerprint != fingerprint {
		m.pendingList = reason
		return
	}
	if l := c.listLocked(m, reason, nil); l != nil {
		c.list(l)
	}
}
