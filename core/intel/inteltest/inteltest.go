// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package inteltest builds tiny MaxMind-format database fixtures for tests,
// so GeoIP code is exercised against real .mmdb files instead of stubs.
// Test-support only; never import it from production code.
package inteltest

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// WriteCountryDB writes a GeoLite2-Country-shaped database mapping each CIDR
// to an ISO country code, and returns its path.
func WriteCountryDB(t testing.TB, dir string, networks map[string]string) string {
	t.Helper()
	records := map[string]mmdbtype.DataType{}
	for cidr, iso := range networks {
		records[cidr] = mmdbtype.Map{
			"country": mmdbtype.Map{"iso_code": mmdbtype.String(iso)},
		}
	}
	return writeDB(t, filepath.Join(dir, "country.mmdb"), "GeoLite2-Country", records)
}

// CityRecord is one network's entry in a GeoLite2-City-shaped fixture. Only
// Country is universal in the real database: city and subdivision are absent
// for roughly a fifth of networks, so leaving those fields empty is a
// realistic case worth testing, not a malformed one.
type CityRecord struct {
	Country          string // ISO 3166-1 alpha-2, e.g. "NL"
	City             string // English name, "" to omit the city key entirely
	Subdivision      string // ISO code, "" to omit the subdivisions key entirely
	AccuracyRadiusKM uint16 // 0 to omit the location key entirely
}

// WriteCityDB writes a GeoLite2-City-shaped database and returns its path.
// Zero-valued fields are omitted from the written record rather than encoded
// as empty values, so a fixture can reproduce the partial coverage the real
// database has (see CityRecord).
func WriteCityDB(t testing.TB, dir string, networks map[string]CityRecord) string {
	t.Helper()
	records := map[string]mmdbtype.DataType{}
	for cidr, rec := range networks {
		m := mmdbtype.Map{
			"country": mmdbtype.Map{"iso_code": mmdbtype.String(rec.Country)},
		}
		if rec.City != "" {
			m["city"] = mmdbtype.Map{
				"names": mmdbtype.Map{"en": mmdbtype.String(rec.City)},
			}
		}
		if rec.Subdivision != "" {
			m["subdivisions"] = mmdbtype.Slice{
				mmdbtype.Map{"iso_code": mmdbtype.String(rec.Subdivision)},
			}
		}
		if rec.AccuracyRadiusKM != 0 {
			m["location"] = mmdbtype.Map{
				"accuracy_radius": mmdbtype.Uint16(rec.AccuracyRadiusKM),
			}
		}
		records[cidr] = m
	}
	return writeDB(t, filepath.Join(dir, "city.mmdb"), "GeoLite2-City", records)
}

// WriteASNDB writes a GeoLite2-ASN-shaped database mapping each CIDR to an
// AS number (organisation derived from the number), and returns its path.
func WriteASNDB(t testing.TB, dir string, networks map[string]uint32) string {
	t.Helper()
	records := map[string]mmdbtype.DataType{}
	for cidr, asn := range networks {
		records[cidr] = mmdbtype.Map{
			"autonomous_system_number":       mmdbtype.Uint32(asn),
			"autonomous_system_organization": mmdbtype.String("Test AS"),
		}
	}
	return writeDB(t, filepath.Join(dir, "asn.mmdb"), "GeoLite2-ASN", records)
}

func writeDB(t testing.TB, path, dbType string, records map[string]mmdbtype.DataType) string {
	t.Helper()
	// Tests use TEST-NET/documentation ranges, which are "reserved" to the
	// writer unless explicitly included.
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            dbType,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		t.Fatalf("mmdbwriter.New: %v", err)
	}
	for cidr, rec := range records {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("bad CIDR %q: %v", cidr, err)
		}
		if err := w.Insert(network, rec); err != nil {
			t.Fatalf("insert %s: %v", cidr, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}
