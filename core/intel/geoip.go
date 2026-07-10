// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package intel

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// mmdbKind is the record schema expected from a database, so a country_db
// accidentally pointed at an ASN file (or vice versa) is rejected instead of
// silently decoding zero values and never matching any geo rule.
type mmdbKind string

const (
	kindCountry mmdbKind = "country"
	kindASN     mmdbKind = "ASN"
)

// matches checks a database's self-declared type. Substring matching, because
// publishers vary the exact name (GeoLite2-Country, DBIP-Country-Lite, ...)
// and richer products that embed the same fields (City, Enterprise, ISP)
// are equally usable.
func (k mmdbKind) matches(dbType string) bool {
	t := strings.ToLower(dbType)
	var accepted []string
	switch k {
	case kindCountry:
		accepted = []string{"country", "city", "enterprise", "location"}
	case kindASN:
		accepted = []string{"asn", "isp", "enterprise"}
	}
	for _, s := range accepted {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}

// mmdbReader wraps maxminddb.Reader with a reference count: the library
// forbids Close concurrently with lookups, and the reader memory-maps the
// file, so unmapping under an in-flight Lookup could fault. The count starts
// at 1 for the owning mmdbFile; each lookup holds one more; whoever drops it
// to zero closes the mmap. A hot reload therefore retires the old reader
// exactly when its last lookup finishes.
type mmdbReader struct {
	*maxminddb.Reader
	refs atomic.Int64
}

func newMMDBReader(r *maxminddb.Reader) *mmdbReader {
	m := &mmdbReader{Reader: r}
	m.refs.Store(1)
	return m
}

// tryAcquire takes a reference, failing when the reader is already retired.
func (r *mmdbReader) tryAcquire() bool {
	for {
		n := r.refs.Load()
		if n <= 0 {
			return false
		}
		if r.refs.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (r *mmdbReader) release() {
	if r.refs.Add(-1) == 0 {
		_ = r.Reader.Close()
	}
}

// mmdbFile is one MaxMind-format database (Country or ASN, from MaxMind
// GeoLite2/GeoIP2, DB-IP or any other publisher) with hot reload: geoipupdate
// and friends replace the file atomically via rename, so a size/mtime change
// is the reload signal. A reload that fails to open keeps the previous
// database rather than dropping geo data.
type mmdbFile struct {
	path   string
	kind   mmdbKind
	reader atomic.Pointer[mmdbReader]

	// Last-seen stat, touched only by the poll goroutine.
	mtime time.Time
	size  int64
}

func openMMDB(path string, kind mmdbKind) (*mmdbFile, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb %s: %w", path, err)
	}
	if !kind.matches(r.Metadata.DatabaseType) {
		_ = r.Close()
		return nil, fmt.Errorf("open mmdb %s: %q is not a %s database", path, r.Metadata.DatabaseType, kind)
	}
	f := &mmdbFile{path: path, kind: kind}
	f.reader.Store(newMMDBReader(r))
	if st, err := os.Stat(path); err == nil {
		f.mtime, f.size = st.ModTime(), st.Size()
	}
	return f, nil
}

// acquire returns the current reader with a reference held, or nil when the
// file is closed. Losing the race with a concurrent swap just means loading
// the freshly swapped-in pointer.
func (f *mmdbFile) acquire() *mmdbReader {
	for {
		r := f.reader.Load()
		if r == nil {
			return nil
		}
		if r.tryAcquire() {
			return r
		}
	}
}

// maybeReload swaps in the file's current contents when its stat changed.
// A failed open records the stat anyway so a broken file does not log every
// poll; any later change re-triggers the load.
func (f *mmdbFile) maybeReload(log *slog.Logger) {
	st, err := os.Stat(f.path)
	if err != nil {
		log.Warn("geoip database unreadable, keeping loaded data", "file", f.path, "err", err)
		return
	}
	if st.ModTime().Equal(f.mtime) && st.Size() == f.size {
		return
	}
	f.mtime, f.size = st.ModTime(), st.Size()
	r, err := maxminddb.Open(f.path)
	if err != nil {
		log.Error("geoip database reload failed, keeping previous data", "file", f.path, "err", err)
		return
	}
	if !f.kind.matches(r.Metadata.DatabaseType) {
		_ = r.Close()
		log.Error("geoip database reload rejected: wrong type, keeping previous data",
			"file", f.path, "type", r.Metadata.DatabaseType, "want", string(f.kind))
		return
	}
	if old := f.reader.Swap(newMMDBReader(r)); old != nil {
		old.release()
	}
	log.Info("geoip database reloaded", "file", f.path, "type", r.Metadata.DatabaseType)
}

func (f *mmdbFile) close() {
	if r := f.reader.Swap(nil); r != nil {
		r.release()
	}
}

// country returns the ISO 3166-1 alpha-2 code for addr, or "" when the
// database has no record. located-country wins; registered_country is the
// fallback (many hosting ranges carry only the latter).
func (f *mmdbFile) country(addr netip.Addr) (string, error) {
	r := f.acquire()
	if r == nil {
		return "", nil
	}
	defer r.release()
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"registered_country"`
	}
	if err := r.Lookup(addr).Decode(&rec); err != nil {
		return "", err
	}
	if rec.Country.ISOCode != "" {
		return rec.Country.ISOCode, nil
	}
	return rec.RegisteredCountry.ISOCode, nil
}

// asn returns the autonomous system number and organisation for addr, or
// (0, "") when the database has no record.
func (f *mmdbFile) asn(addr netip.Addr) (uint32, string, error) {
	r := f.acquire()
	if r == nil {
		return 0, "", nil
	}
	defer r.release()
	var rec struct {
		Number uint32 `maxminddb:"autonomous_system_number"`
		Org    string `maxminddb:"autonomous_system_organization"`
	}
	if err := r.Lookup(addr).Decode(&rec); err != nil {
		return 0, "", err
	}
	return rec.Number, rec.Org, nil
}

// DBStatus describes one loaded database for the admin API.
type DBStatus struct {
	Path  string    `json:"path"`
	Type  string    `json:"type"`
	Built time.Time `json:"built"`
}

func (f *mmdbFile) status() *DBStatus {
	r := f.acquire()
	if r == nil {
		return nil
	}
	defer r.release()
	return &DBStatus{
		Path:  f.path,
		Type:  r.Metadata.DatabaseType,
		Built: time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC(),
	}
}
