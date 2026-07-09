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
