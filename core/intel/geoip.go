// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package intel

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// mmdbCloseGrace is how long a replaced reader stays open after a hot reload.
// The reader memory-maps the file, so closing it under an in-flight Lookup
// would fault; lookups take microseconds, so a minute is generous.
const mmdbCloseGrace = time.Minute

// mmdbFile is one MaxMind-format database (Country or ASN, from MaxMind
// GeoLite2/GeoIP2, DB-IP or any other publisher) with hot reload: geoipupdate
// and friends replace the file atomically via rename, so a size/mtime change
// is the reload signal. A reload that fails to open keeps the previous
// database rather than dropping geo data.
type mmdbFile struct {
	path   string
	reader atomic.Pointer[maxminddb.Reader]

	// Last-seen stat, touched only by the poll goroutine.
	mtime time.Time
	size  int64
}

func openMMDB(path string) (*mmdbFile, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open mmdb %s: %w", path, err)
	}
	f := &mmdbFile{path: path}
	f.reader.Store(r)
	if st, err := os.Stat(path); err == nil {
		f.mtime, f.size = st.ModTime(), st.Size()
	}
	return f, nil
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
	old := f.reader.Swap(r)
	if old != nil {
		time.AfterFunc(mmdbCloseGrace, func() { _ = old.Close() })
	}
	log.Info("geoip database reloaded", "file", f.path, "type", r.Metadata.DatabaseType)
}

func (f *mmdbFile) close() {
	if r := f.reader.Swap(nil); r != nil {
		_ = r.Close()
	}
}

// country returns the ISO 3166-1 alpha-2 code for addr, or "" when the
// database has no record. located-country wins; registered_country is the
// fallback (many hosting ranges carry only the latter).
func (f *mmdbFile) country(addr netip.Addr) (string, error) {
	r := f.reader.Load()
	if r == nil {
		return "", nil
	}
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
	r := f.reader.Load()
	if r == nil {
		return 0, "", nil
	}
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
	r := f.reader.Load()
	if r == nil {
		return nil
	}
	return &DBStatus{
		Path:  f.path,
		Type:  r.Metadata.DatabaseType,
		Built: time.Unix(int64(r.Metadata.BuildEpoch), 0).UTC(),
	}
}
