// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package intel

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/intel/inteltest"
)

func TestParseList(t *testing.T) {
	raw := []byte(`
# a comment
; another comment style
198.51.100.0/24
203.0.113.9          # inline comment
2001:db8::/32 ; inline too
not-an-ip
300.300.300.300/8
`)
	prefixes, invalid := ParseList(raw)
	if len(prefixes) != 3 {
		t.Fatalf("want 3 prefixes, got %d: %v", len(prefixes), prefixes)
	}
	if invalid != 2 {
		t.Fatalf("want 2 invalid lines, got %d", invalid)
	}
}

func TestRangeSetContains(t *testing.T) {
	prefixes, invalid := ParseList([]byte("198.51.100.0/24\n198.51.100.128/25\n203.0.113.9\n2001:db8::/32\n"))
	if invalid != 0 {
		t.Fatalf("unexpected invalid lines: %d", invalid)
	}
	set := newRangeSet(prefixes)
	for _, tc := range []struct {
		ip   string
		want bool
	}{
		{"198.51.100.0", true},
		{"198.51.100.255", true}, // overlap-merged
		{"198.51.101.0", false},
		{"203.0.113.9", true},
		{"203.0.113.10", false},
		{"2001:db8:1::1", true},
		{"2001:db9::1", false},
		{"::ffff:203.0.113.9", true}, // 4-in-6 maps onto the v4 entry
	} {
		if got := set.Contains(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Errorf("Contains(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestRangeSetEmpty(t *testing.T) {
	if newRangeSet(nil).Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("empty set must match nothing")
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProviderGeoLookup(t *testing.T) {
	dir := t.TempDir()
	countryDB := inteltest.WriteCountryDB(t, dir, map[string]string{
		"198.51.100.0/24": "NL",
		"2001:db8::/32":   "DE",
	})
	asnDB := inteltest.WriteASNDB(t, dir, map[string]uint32{
		"198.51.100.0/24": 64500,
	})
	p, err := New(Config{LocationDB: countryDB, ASNDB: asnDB}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	info := p.Lookup(netip.MustParseAddr("198.51.100.7"))
	if info.Country != "NL" || info.ASN != 64500 || info.ASOrg != "Test AS" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if info = p.Lookup(netip.MustParseAddr("2001:db8::1")); info.Country != "DE" || info.ASN != 0 {
		t.Fatalf("unexpected v6 info: %+v", info)
	}
	// Unknown IP (private range): all zero values.
	if info = p.Lookup(netip.MustParseAddr("10.0.0.1")); info != (Info{}) {
		t.Fatalf("want zero Info for unknown IP, got %+v", info)
	}
	// 4-in-6 client addresses must still hit the v4 entry.
	if info = p.Lookup(netip.MustParseAddr("::ffff:198.51.100.7")); info.Country != "NL" {
		t.Fatalf("4-in-6 lookup failed: %+v", info)
	}
}

// TestProviderCityLookup covers a City database in the location_db slot: the
// country fields must behave exactly as with a Country file, and the extra
// city/subdivision/radius detail must come through the same single lookup.
func TestProviderCityLookup(t *testing.T) {
	dir := t.TempDir()
	cityDB := inteltest.WriteCityDB(t, dir, map[string]inteltest.CityRecord{
		"198.51.100.0/24": {Country: "NL", City: "Schagen", Subdivision: "NH", AccuracyRadiusKM: 10},
		// Country-level record: the real database leaves city and subdivision
		// out for ~20% of networks, and pins those at a huge radius.
		"203.0.113.0/24": {Country: "US", AccuracyRadiusKM: 1000},
	})
	p, err := New(Config{LocationDB: cityDB}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	info := p.Lookup(netip.MustParseAddr("198.51.100.7"))
	if info.Country != "NL" || info.City != "Schagen" || info.Subdivision != "NH" {
		t.Fatalf("city record: %+v", info)
	}
	if info.AccuracyRadiusKM != 10 {
		t.Fatalf("accuracy radius = %d, want 10", info.AccuracyRadiusKM)
	}

	// A record without city/subdivision must degrade to country only rather
	// than erroring or panicking on the empty subdivisions slice.
	info = p.Lookup(netip.MustParseAddr("203.0.113.7"))
	if info.Country != "US" || info.City != "" || info.Subdivision != "" {
		t.Fatalf("country-only record in a City db: %+v", info)
	}
	if info.AccuracyRadiusKM != 1000 {
		t.Fatalf("accuracy radius = %d, want 1000", info.AccuracyRadiusKM)
	}

	if info = p.Lookup(netip.MustParseAddr("10.0.0.1")); info != (Info{}) {
		t.Fatalf("want zero Info for unknown IP, got %+v", info)
	}
}

// TestCountryDBOmitsCityFields is the degradation guarantee: the common
// deployment points location_db at a Country database, and must see exactly
// what it saw before city support existed.
func TestCountryDBOmitsCityFields(t *testing.T) {
	dir := t.TempDir()
	countryDB := inteltest.WriteCountryDB(t, dir, map[string]string{
		"198.51.100.0/24": "NL",
	})
	p, err := New(Config{LocationDB: countryDB}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	info := p.Lookup(netip.MustParseAddr("198.51.100.7"))
	if info.Country != "NL" {
		t.Fatalf("country = %q, want NL", info.Country)
	}
	if info.City != "" || info.Subdivision != "" || info.AccuracyRadiusKM != 0 {
		t.Fatalf("a Country database must yield no city detail, got %+v", info)
	}
}

// TestCityDBAcceptedAsLocationDB pins the type guard: a City file is a valid
// location database, so a future edit to mmdbKind.matches cannot silently
// start rejecting it (nor start accepting an ASN file, which would decode
// zero values and make every geo rule inert).
func TestCityDBAcceptedAsLocationDB(t *testing.T) {
	dir := t.TempDir()
	cityDB := inteltest.WriteCityDB(t, dir, map[string]inteltest.CityRecord{
		"198.51.100.0/24": {Country: "NL", City: "Schagen"},
	})
	p, err := New(Config{LocationDB: cityDB}, testLogger())
	if err != nil {
		t.Fatalf("a City database must be accepted as location_db: %v", err)
	}
	p.Close()

	asnDB := inteltest.WriteASNDB(t, dir, map[string]uint32{"198.51.100.0/24": 64500})
	if _, err := New(Config{LocationDB: asnDB}, testLogger()); err == nil {
		t.Fatal("an ASN database as location_db must fail startup")
	}
}

func TestProviderNilAndEmpty(t *testing.T) {
	var p *Provider
	if p.Lookup(netip.MustParseAddr("192.0.2.1")) != (Info{}) {
		t.Fatal("nil provider must return zero Info")
	}
	if _, ok := p.FeedMatch(netip.MustParseAddr("192.0.2.1"), FeedActionDeny); ok {
		t.Fatal("nil provider must match nothing")
	}
	p.Start()
	p.Close()

	got, err := New(Config{}, testLogger())
	if err != nil || got != nil {
		t.Fatalf("empty config: want (nil, nil), got (%v, %v)", got, err)
	}
}

func TestMMDBHotReload(t *testing.T) {
	dir := t.TempDir()
	path := inteltest.WriteCountryDB(t, dir, map[string]string{"198.51.100.0/24": "NL"})
	p, err := New(Config{LocationDB: path}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	addr := netip.MustParseAddr("198.51.100.7")
	if got := p.Lookup(addr).Country; got != "NL" {
		t.Fatalf("want NL, got %q", got)
	}

	// Replace the database (new content, new mtime) and poll once.
	next := inteltest.WriteCountryDB(t, t.TempDir(), map[string]string{"198.51.100.0/24": "BE"})
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	p.country.maybeReload(testLogger())
	if got := p.Lookup(addr).Country; got != "BE" {
		t.Fatalf("after reload want BE, got %q", got)
	}
}

func TestMMDBHotReloadDetectsSameSizeAndMtimeReplacement(t *testing.T) {
	dir := t.TempDir()
	path := inteltest.WriteCountryDB(t, dir, map[string]string{"198.51.100.0/24": "NL"})
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{LocationDB: path}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	next := inteltest.WriteCountryDB(t, t.TempDir(), map[string]string{"198.51.100.0/24": "BE"})
	replacement, err := os.Stat(next)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Size() != original.Size() {
		t.Fatalf("fixture sizes differ: original=%d replacement=%d", original.Size(), replacement.Size())
	}
	if err := os.Chtimes(next, original.ModTime(), original.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}

	p.country.maybeReload(testLogger())
	addr := netip.MustParseAddr("198.51.100.7")
	if got := p.Lookup(addr).Country; got != "BE" {
		t.Fatalf("same-size, same-mtime replacement was missed: got %q, want BE", got)
	}
}

func TestMMDBWrongTypeFailsStartup(t *testing.T) {
	dir := t.TempDir()
	countryDB := inteltest.WriteCountryDB(t, dir, map[string]string{"198.51.100.0/24": "NL"})
	asnDB := inteltest.WriteASNDB(t, dir, map[string]uint32{"198.51.100.0/24": 64500})
	if _, err := New(Config{LocationDB: asnDB}, testLogger()); err == nil {
		t.Fatal("an ASN database as location_db must fail startup")
	}
	if _, err := New(Config{ASNDB: countryDB}, testLogger()); err == nil {
		t.Fatal("a country database as asn_db must fail startup")
	}
}

func TestMMDBReloadWrongTypeKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	path := inteltest.WriteCountryDB(t, dir, map[string]string{"198.51.100.0/24": "NL"})
	p, err := New(Config{LocationDB: path}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Replace the country file with an ASN database and poll: the reload
	// must be rejected and the loaded country data kept.
	next := inteltest.WriteASNDB(t, t.TempDir(), map[string]uint32{"198.51.100.0/24": 64500})
	if err := os.Rename(next, path); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	p.country.maybeReload(testLogger())
	if got := p.Lookup(netip.MustParseAddr("198.51.100.7")).Country; got != "NL" {
		t.Fatalf("want NL from the kept database, got %q", got)
	}
}

func TestCloseCancelsInflightFetch(t *testing.T) {
	var once sync.Once
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-r.Context().Done() // stall until the client gives up
	}))
	defer srv.Close()

	p, err := New(Config{Feeds: []FeedConfig{
		{Name: "slow", URL: srv.URL, Refresh: time.Hour, Action: FeedActionDeny},
	}}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	p.Start()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("fetch never reached the server")
	}
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on the in-flight fetch")
	}
}

func TestFileFeedLoadAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.list")
	if err := os.WriteFile(path, []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Feeds: []FeedConfig{
		{Name: "local", File: path, Action: FeedActionDeny},
	}}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	if name, ok := p.FeedMatch(netip.MustParseAddr("203.0.113.5"), FeedActionDeny); !ok || name != "local" {
		t.Fatalf("want deny hit on local, got (%q, %v)", name, ok)
	}
	if _, ok := p.FeedMatch(netip.MustParseAddr("203.0.113.5"), FeedActionChallenge); ok {
		t.Fatal("action filter must not match a deny feed as challenge")
	}

	// Content change is picked up by the file poll path.
	if err := os.WriteFile(path, []byte("192.0.2.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := p.feeds[0].loadFile(false, testLogger()); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.FeedMatch(netip.MustParseAddr("203.0.113.5"), FeedActionDeny); ok {
		t.Fatal("old entries must be gone after reload")
	}
	if _, ok := p.FeedMatch(netip.MustParseAddr("192.0.2.5"), FeedActionDeny); !ok {
		t.Fatal("new entries must match after reload")
	}
}

func TestFileFeedMissingFailsStartup(t *testing.T) {
	_, err := New(Config{Feeds: []FeedConfig{
		{Name: "gone", File: "/nonexistent/feed.list", Action: FeedActionDeny},
	}}, testLogger())
	if err == nil {
		t.Fatal("missing file feed must fail startup")
	}
}

func TestURLFeedFetchAndCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# feed\n203.0.113.0/24\n"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	cfg := Config{CacheDir: cacheDir, Feeds: []FeedConfig{
		{Name: "remote", URL: srv.URL, Refresh: time.Hour, Action: FeedActionChallenge},
	}}
	p, err := New(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.feeds[0].fetch(t.Context(), p.client, cacheDir, testLogger()); err != nil {
		t.Fatal(err)
	}
	if name, ok := p.FeedMatch(netip.MustParseAddr("203.0.113.5"), FeedActionChallenge); !ok || name != "remote" {
		t.Fatalf("want challenge hit on remote, got (%q, %v)", name, ok)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "remote.list")); err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	p.Close()

	// A fresh provider seeds from the cache without any fetch.
	p2, err := New(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p2.Close()
	if mtime := p2.feeds[0].loadCache(cacheDir); mtime.IsZero() {
		t.Fatal("cache seed failed")
	}
	if _, ok := p2.FeedMatch(netip.MustParseAddr("203.0.113.5"), FeedActionChallenge); !ok {
		t.Fatal("cache-seeded feed must match")
	}
	st := p2.feeds[0].status()
	if !st.Loaded || st.LoadedFrom != "cache" || st.Entries != 1 {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestFeedRejectsGarbageBody(t *testing.T) {
	f := &feed{cfg: FeedConfig{Name: "x", Action: FeedActionDeny}}
	if _, err := f.install([]byte("<!doctype html><html>oops</html>"), "url", time.Now()); err == nil {
		t.Fatal("an HTML body must be rejected")
	}
	// An empty body (feed legitimately empty) is fine.
	if _, err := f.install(nil, "url", time.Now()); err != nil {
		t.Fatalf("empty body: %v", err)
	}
}

func TestProviderStatus(t *testing.T) {
	dir := t.TempDir()
	countryDB := inteltest.WriteCountryDB(t, dir, map[string]string{"198.51.100.0/24": "NL"})
	feedFile := filepath.Join(dir, "f.list")
	if err := os.WriteFile(feedFile, []byte("192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{LocationDB: countryDB, Feeds: []FeedConfig{
		{Name: "f", File: feedFile, Action: FeedActionDeny},
	}}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	s := p.Status()
	if s.LocationDB == nil || s.LocationDB.Type != "GeoLite2-Country" || s.ASNDB != nil {
		t.Fatalf("unexpected db status: %+v", s)
	}
	if len(s.Feeds) != 1 || !s.Feeds[0].Loaded || s.Feeds[0].Entries != 1 {
		t.Fatalf("unexpected feed status: %+v", s.Feeds)
	}
}

// TestOfficialMaxMindTestData runs the reader against MaxMind's own published
// test databases (see testdata/README.md), so the decode structs are proven
// against files MaxMind actually ships, not only mmdbwriter output.
func TestOfficialMaxMindTestData(t *testing.T) {
	p, err := New(Config{
		LocationDB: "testdata/GeoIP2-Country-Test.mmdb",
		ASNDB:      "testdata/GeoLite2-ASN-Test.mmdb",
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	for _, tc := range []struct {
		ip      string
		country string
		asn     uint32
		asOrg   string
	}{
		{"81.2.69.142", "GB", 0, ""},
		{"89.160.20.128", "SE", 29518, "Bredband2 AB"}, // in both databases
		{"2001:218::1", "JP", 0, ""},
		{"1.128.0.0", "", 1221, "Telstra Pty Ltd"},
		{"12.81.92.1", "", 7018, "AT&T Services"},
		{"2600:6000::1", "", 237, "Merit Network Inc."},
		{"10.0.0.1", "", 0, ""}, // private: no records anywhere
	} {
		info := p.Lookup(netip.MustParseAddr(tc.ip))
		if info.Country != tc.country || info.ASN != tc.asn || info.ASOrg != tc.asOrg {
			t.Errorf("Lookup(%s) = %+v, want {%s %d %s}", tc.ip, info, tc.country, tc.asn, tc.asOrg)
		}
	}

	s := p.Status()
	if s.LocationDB == nil || s.LocationDB.Type != "GeoIP2-Country" {
		t.Errorf("country db status: %+v", s.LocationDB)
	}
	if s.ASNDB == nil || s.ASNDB.Type != "GeoLite2-ASN" {
		t.Errorf("asn db status: %+v", s.ASNDB)
	}
}
