// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package intel supplies IP intelligence to the decision pipeline: GeoIP
// country and ASN lookups from MaxMind-format (.mmdb) databases, and
// membership in external IP reputation feeds (plain-text IP/CIDR lists,
// fetched periodically or read from local files). Everything is loaded into
// memory and swapped atomically, so lookups on the auth hot path never take
// a lock or touch the disk/network; refresh work happens in the background
// and a failed refresh keeps the last good data (fail-open, like the rest of
// Guardian).
package intel

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melroy89/angie-guardian/core/metrics"
	"github.com/melroy89/angie-guardian/internal/jitter"
)

// pollInterval is how often mmdb files and local file feeds are checked for
// changes. GeoIP databases update at most daily, so a minute is plenty.
const pollInterval = time.Minute

// Config is what the Provider needs, assembled by the core config loader.
type Config struct {
	// LocationDB is a MaxMind-format Country or City database ("" = no
	// country data). City is a superset of Country, so both satisfy country
	// lookups; only City also yields city/subdivision detail.
	LocationDB string
	ASNDB      string // MaxMind-format ASN database, "" = no ASN data
	CacheDir   string // persisted copies of URL feeds, "" = no persistence
	Feeds      []FeedConfig
}

// Info is one IP's intelligence: zero values mean "unknown" (no database
// configured, or the IP simply has no record; private ranges never do).
type Info struct {
	Country string `json:"country,omitempty"` // ISO 3166-1 alpha-2, upper case
	ASN     uint32 `json:"asn,omitzero"`
	ASOrg   string `json:"as_org,omitempty"`

	// City and Subdivision are only ever populated from a City-class
	// location_db, and even then not for every network (~79% / ~80%), so
	// treat "" as normal rather than exceptional.
	City        string `json:"city,omitempty"`        // English name, e.g. "Schagen"
	Subdivision string `json:"subdivision,omitempty"` // ISO code, e.g. "NH"

	// AccuracyRadiusKM qualifies City/Subdivision: it is the radius of the
	// area the record describes, not a precision. Large values are common
	// (~29% of networks are 200km+), so anything showing a locality to an
	// operator should show this alongside it. Never a coordinate: see
	// geoRecord.AccuracyRadiusKM.
	AccuracyRadiusKM uint16 `json:"accuracy_radius_km,omitzero"`
}

// FeedHit names one feed an IP appears in.
type FeedHit struct {
	Feed   string `json:"feed"`
	Action string `json:"action"`
}

// Provider owns the loaded databases and feeds. A nil *Provider is valid and
// answers every lookup with "unknown"/"no match", so callers need no checks
// when intel is unconfigured.
type Provider struct {
	country *mmdbFile
	asn     *mmdbFile
	feeds   []*feed

	cacheDir string
	client   *http.Client
	log      *slog.Logger
	metrics  atomic.Pointer[metrics.Metrics]

	// geoFn overrides mmdb lookups in tests.
	geoFn func(netip.Addr) Info

	// ctx is cancelled by Close: it both stops the background loops and
	// aborts any in-flight feed fetch, so shutdown never waits out the
	// HTTP client timeout on a stalled remote.
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New loads the configured databases and feeds. Local resources (mmdb files,
// file feeds) must load or startup fails, matching the WAF rules files'
// fail-fast policy. URL feeds must NOT block or fail startup on a slow or
// down remote: they seed from the cache dir when possible and fetch in the
// background once Start is called. Returns (nil, nil) when nothing is
// configured.
func New(cfg Config, log *slog.Logger) (*Provider, error) {
	if cfg.LocationDB == "" && cfg.ASNDB == "" && len(cfg.Feeds) == 0 {
		return nil, nil
	}
	p := &Provider{
		cacheDir: cfg.CacheDir,
		client:   &http.Client{Timeout: 90 * time.Second},
		log:      log,
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	var err error
	if cfg.LocationDB != "" {
		if p.country, err = openMMDB(cfg.LocationDB, kindCountry); err != nil {
			return nil, err
		}
	}
	if cfg.ASNDB != "" {
		if p.asn, err = openMMDB(cfg.ASNDB, kindASN); err != nil {
			p.closeDBs()
			return nil, err
		}
	}
	if cfg.CacheDir != "" {
		if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
			p.closeDBs()
			return nil, fmt.Errorf("reputation cache_dir: %w", err)
		}
	}
	for i := range cfg.Feeds {
		f := &feed{cfg: cfg.Feeds[i]}
		if f.cfg.File != "" {
			if err := f.loadFile(true, log); err != nil {
				p.closeDBs()
				return nil, err
			}
		}
		p.feeds = append(p.feeds, f)
	}
	return p, nil
}

// Start launches the background refresh work: one goroutine per URL feed and
// one poller for mmdb files and file feeds.
func (p *Provider) Start() {
	if p == nil {
		return
	}
	for _, f := range p.feeds {
		if f.cfg.URL == "" {
			continue
		}
		p.wg.Add(1)
		go p.refreshLoop(f)
	}
	p.wg.Add(1)
	go p.pollLoop()
}

// SeedURLFeedsFrom carries forward the last good immutable state for URL feeds
// whose name and source are unchanged across an engine config reload. URL
// refresh is intentionally asynchronous so a slow remote never blocks reload;
// without this handoff the new provider would temporarily (or, while the
// remote is down, indefinitely) forget a deny feed that the old snapshot had
// already loaded. Call before Start, while the new provider is not live yet.
func (p *Provider) SeedURLFeedsFrom(old *Provider) {
	if p == nil || old == nil {
		return
	}
	type feedKey struct{ name, url string }
	loaded := make(map[feedKey]*feedState, len(old.feeds))
	for _, f := range old.feeds {
		if f.cfg.URL == "" {
			continue
		}
		if st := f.state.Load(); st != nil {
			loaded[feedKey{f.cfg.Name, f.cfg.URL}] = st
		}
	}
	for _, f := range p.feeds {
		if f.cfg.URL == "" || f.state.Load() != nil {
			continue
		}
		if st := loaded[feedKey{f.cfg.Name, f.cfg.URL}]; st != nil {
			f.state.Store(st)
		}
	}
}

// Close stops the background work (cancelling any in-flight feed fetch) and
// releases the databases.
func (p *Provider) Close() {
	if p == nil {
		return
	}
	p.cancel()
	p.wg.Wait()
	p.closeDBs()
}

func (p *Provider) closeDBs() {
	if p.country != nil {
		p.country.close()
	}
	if p.asn != nil {
		p.asn.close()
	}
}

// SetMetrics attaches the metrics sink (nil-safe, called once at startup).
func (p *Provider) SetMetrics(m *metrics.Metrics) {
	if p != nil {
		p.metrics.Store(m)
	}
}

// refreshLoop drives one URL feed: seed from cache, then fetch on the
// refresh interval, retrying sooner after failures.
func (p *Provider) refreshLoop(f *feed) {
	defer p.wg.Done()
	// A fresh-enough cached copy defers the first fetch to when the cache
	// would have expired; anything else fetches (almost) immediately.
	delay := time.Second
	if mtime := f.loadCache(p.cacheDir); !mtime.IsZero() {
		if remaining := f.cfg.Refresh - time.Since(mtime); remaining > delay {
			delay = remaining
		}
		p.log.Info("feed loaded from cache", "feed", f.cfg.Name,
			"entries", f.state.Load().entries, "age", time.Since(mtime).Round(time.Second))
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-timer.C:
		}
		next := f.cfg.Refresh
		if err := f.fetch(p.ctx, p.client, p.cacheDir, p.log); err != nil {
			if p.ctx.Err() != nil {
				return // shutting down, the error is just the cancellation
			}
			msg := err.Error()
			f.lastErr.Store(&msg)
			p.log.Warn("feed refresh failed, keeping loaded entries",
				"feed", f.cfg.Name, "url", f.cfg.URL, "err", err)
			next = min(feedRetryInterval, f.cfg.Refresh)
		} else {
			f.lastErr.Store(nil)
			st := f.state.Load()
			p.log.Info("feed refreshed", "feed", f.cfg.Name, "entries", st.entries)
		}
		p.reportFeed(f)
		// Jitter both the steady refresh and the retry: a fleet that lost the
		// feed origin together must not re-hammer it in lockstep.
		timer.Reset(jitter.Frac(next, jitter.Fraction))
	}
}

// pollLoop watches local files (mmdb databases and file feeds) for changes.
func (p *Provider) pollLoop() {
	defer p.wg.Done()
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-t.C:
			if p.country != nil {
				p.country.maybeReload(p.log)
			}
			if p.asn != nil {
				p.asn.maybeReload(p.log)
			}
			for _, f := range p.feeds {
				if f.cfg.File != "" {
					_ = f.loadFile(false, p.log)
					p.reportFeed(f)
				}
			}
		}
	}
}

func (p *Provider) reportFeed(f *feed) {
	entries := 0
	if st := f.state.Load(); st != nil {
		entries = st.entries
	}
	p.metrics.Load().FeedRefresh(f.cfg.Name, entries, f.lastErr.Load() != nil)
}

// HasCountry / HasASN report whether the respective database is loaded, so
// config validation can refuse geo rules that could never match.
func (p *Provider) HasCountry() bool { return p != nil && p.country != nil }
func (p *Provider) HasASN() bool     { return p != nil && p.asn != nil }

// Lookup returns the country/ASN intelligence for addr. Lookup errors are
// deliberately swallowed into "unknown": a corrupt record must degrade to
// the default action, not break the pipeline (which would fail open anyway).
func (p *Provider) Lookup(addr netip.Addr) Info {
	if p == nil {
		return Info{}
	}
	if p.geoFn != nil {
		return p.geoFn(addr)
	}
	addr = addr.Unmap()
	var info Info
	if p.country != nil {
		g, err := p.country.geo(addr)
		if err != nil {
			p.log.Warn("location lookup failed", "ip", addr, "err", err)
		}
		info.Country, info.City = g.Country, g.City
		info.Subdivision, info.AccuracyRadiusKM = g.Subdivision, g.AccuracyRadiusKM
	}
	if p.asn != nil {
		n, org, err := p.asn.asn(addr)
		if err != nil {
			p.log.Warn("asn lookup failed", "ip", addr, "err", err)
		}
		info.ASN, info.ASOrg = n, org
	}
	return info
}

// FeedMatch reports the first configured feed with the given action that
// contains addr. Config order is precedence order.
func (p *Provider) FeedMatch(addr netip.Addr, action string) (string, bool) {
	if p == nil {
		return "", false
	}
	for _, f := range p.feeds {
		if f.cfg.Action == action && f.contains(addr) {
			return f.cfg.Name, true
		}
	}
	return "", false
}

// FeedHits lists every feed containing addr (admin inspection).
func (p *Provider) FeedHits(addr netip.Addr) []FeedHit {
	if p == nil {
		return nil
	}
	var hits []FeedHit
	for _, f := range p.feeds {
		if f.contains(addr) {
			hits = append(hits, FeedHit{Feed: f.cfg.Name, Action: f.cfg.Action})
		}
	}
	return hits
}

// Status is the admin-API view of the whole provider.
type Status struct {
	// LocationDB reports the loaded Country or City database; Type carries
	// which one it actually is (e.g. "GeoLite2-City").
	LocationDB *DBStatus    `json:"location_db,omitempty"`
	ASNDB      *DBStatus    `json:"asn_db,omitempty"`
	Feeds      []FeedStatus `json:"feeds"`
}

func (p *Provider) Status() Status {
	var s Status
	if p == nil {
		return s
	}
	if p.country != nil {
		s.LocationDB = p.country.status()
	}
	if p.asn != nil {
		s.ASNDB = p.asn.status()
	}
	s.Feeds = make([]FeedStatus, 0, len(p.feeds))
	for _, f := range p.feeds {
		s.Feeds = append(s.Feeds, f.status())
	}
	return s
}

// NewStatic builds a Provider from a fixed geo lookup function and in-memory
// feeds, for tests that need intel without mmdb fixtures or a network.
func NewStatic(geoFn func(netip.Addr) Info, feeds ...StaticFeed) *Provider {
	p := &Provider{geoFn: geoFn, log: slog.Default()}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	for _, sf := range feeds {
		prefixes, _ := ParseList([]byte(sf.Entries))
		f := &feed{cfg: FeedConfig{Name: sf.Name, Action: sf.Action}}
		f.state.Store(&feedState{set: newRangeSet(prefixes), entries: len(prefixes), refreshed: time.Now(), source: "static"})
		p.feeds = append(p.feeds, f)
	}
	return p
}

// StaticFeed is NewStatic's in-memory feed: newline-separated IPs/CIDRs.
type StaticFeed struct {
	Name    string
	Action  string
	Entries string
}
