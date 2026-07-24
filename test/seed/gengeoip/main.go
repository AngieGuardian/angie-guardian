// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command gengeoip regenerates the committed GeoIP fixtures the seed config
// points at (test/seed/seed-city.mmdb, test/seed/seed-asn.mmdb). They map the
// seeder's documentation ranges to a spread of countries, cities and ASNs so
// every geo surface of the dashboard lights up during a demo: the Geo columns,
// the world map (Singapore has no shape in the 110m atlas, exercising its
// "Not on map" list), the country offenders rollup, and the IP lookup card.
// One range carries an 800 km accuracy radius on purpose: that is the
// coarse-locality case the dashboard renders dimmed with a tooltip.
//
// The fixtures are committed because guardiand loads them at startup, before
// `make seed` runs. Regenerate only when changing the mapping:
//
//	go generate ./test/seed
//
// (The .mmdb format embeds a build timestamp, so a regeneration always
// produces a new byte identity even with an unchanged mapping.)
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

// cityRecord mirrors the fields the intel provider reads from a City-shaped
// database. City/Subdivision/RadiusKM may be zero: roughly a fifth of real
// GeoLite2-City networks resolve to a country only, and the seed data keeps
// that case (203.0.113.192/26) so the dashboard's "no locality" rendering is
// part of the demo too.
type cityRecord struct {
	Country     string
	City        string
	Subdivision string
	RadiusKM    uint16
}

// The seeder's client pools (test/seed/main.go) and what they resolve to.
var cities = map[string]cityRecord{
	// Legitimate visitors (198.51.100.0/24), split across Europe and the US.
	"198.51.100.0/26":   {Country: "NL", City: "Schagen", Subdivision: "NH", RadiusKM: 10},
	"198.51.100.64/26":  {Country: "DE", City: "Berlin", Subdivision: "BE", RadiusKM: 20},
	"198.51.100.128/26": {Country: "US", City: "Kansas City", Subdivision: "MO", RadiusKM: 800},
	"198.51.100.192/26": {Country: "GB", City: "London", Subdivision: "ENG", RadiusKM: 25},
	// Allowed plain.test traffic.
	"192.0.2.0/24": {Country: "FR", City: "Paris", Subdivision: "IDF", RadiusKM: 10},
	// Scanners, the bad-nonce bot, the star offender.
	"203.0.113.0/25":   {Country: "RU", City: "Moscow", Subdivision: "MOW", RadiusKM: 50},
	"203.0.113.128/26": {Country: "CN", City: "Shanghai", Subdivision: "SH", RadiusKM: 100},
	// Feed + static-denylist ranges: country-only, and one the atlas can't draw.
	"203.0.113.192/26": {Country: "SG"},
	// Honeypot crawlers.
	"198.18.0.0/15": {Country: "BR", City: "Sao Paulo", Subdivision: "SP", RadiusKM: 30},
}

type asnRecord struct {
	Number uint32
	Org    string
}

var asns = map[string]asnRecord{
	"198.51.100.0/24":  {Number: 64500, Org: "Example Broadband BV"},
	"192.0.2.0/24":     {Number: 64501, Org: "Documentation ISP"},
	"203.0.113.0/25":   {Number: 64496, Org: "Bulletproof Hosting Ltd"},
	"203.0.113.128/25": {Number: 64497, Org: "Shady Cloud PTE"},
	"198.18.0.0/15":    {Number: 64502, Org: "Benchmark Cloud Inc"},
}

func main() {
	dir := flag.String("dir", "test/seed", "directory to write the fixtures into")
	flag.Parse()

	cityData := map[string]mmdbtype.DataType{}
	for cidr, rec := range cities {
		m := mmdbtype.Map{
			"country": mmdbtype.Map{"iso_code": mmdbtype.String(rec.Country)},
		}
		if rec.City != "" {
			m["city"] = mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(rec.City)}}
		}
		if rec.Subdivision != "" {
			m["subdivisions"] = mmdbtype.Slice{mmdbtype.Map{"iso_code": mmdbtype.String(rec.Subdivision)}}
		}
		if rec.RadiusKM != 0 {
			m["location"] = mmdbtype.Map{"accuracy_radius": mmdbtype.Uint16(rec.RadiusKM)}
		}
		cityData[cidr] = m
	}
	writeDB(filepath.Join(*dir, "seed-city.mmdb"), "GeoLite2-City", cityData)

	asnData := map[string]mmdbtype.DataType{}
	for cidr, rec := range asns {
		asnData[cidr] = mmdbtype.Map{
			"autonomous_system_number":       mmdbtype.Uint32(rec.Number),
			"autonomous_system_organization": mmdbtype.String(rec.Org),
		}
	}
	writeDB(filepath.Join(*dir, "seed-asn.mmdb"), "GeoLite2-ASN", asnData)
}

func writeDB(path, dbType string, records map[string]mmdbtype.DataType) {
	// The pools are TEST-NET/documentation ranges, which the writer treats as
	// reserved unless explicitly included.
	w, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            dbType,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		fatal("mmdbwriter.New: %v", err)
	}
	// Insert in sorted order so an unchanged mapping produces an unchanged
	// tree (only the embedded build timestamp differs between runs).
	cidrs := make([]string, 0, len(records))
	for cidr := range records {
		cidrs = append(cidrs, cidr)
	}
	sort.Strings(cidrs)
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			fatal("bad CIDR %q: %v", cidr, err)
		}
		if err := w.Insert(network, records[cidr]); err != nil {
			fatal("insert %s: %v", cidr, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		fatal("create %s: %v", path, err)
	}
	defer f.Close()
	if _, err := w.WriteTo(f); err != nil {
		fatal("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s (%s, %d networks)\n", path, dbType, len(records))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gengeoip: "+format+"\n", args...)
	os.Exit(1)
}
