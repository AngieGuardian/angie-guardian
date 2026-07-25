// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package duration

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestParseMatchesStdlib is the compatibility contract. Every duration in
// every guardian.yaml flows through Parse, so a string that used to work must
// keep parsing to the identical value. Inputs without an extended unit are
// delegated to time.ParseDuration outright, which is what makes this hold by
// construction rather than by luck; the test pins it anyway so a future
// "optimisation" that stops delegating gets caught.
func TestParseMatchesStdlib(t *testing.T) {
	inputs := []string{
		"0", "+0", "-0", "1s", "300ms", "1.5h", "2h45m", "1h30m10s",
		"100ns", "5us", "5µs", "5μs", "10ms", "90s", "15m", "24h",
		"-2h45m", "+1h", ".5s", "0.5s", "1e0s", "876000h",
		"1h0m0s", "0s", "1m0.5s", "2562047h47m16.854775807s",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			want, wantErr := time.ParseDuration(in)
			got, gotErr := Parse(in)

			// Beyond Max we deliberately diverge: the stdlib accepts up to
			// ~292 years, we stop at 100y. That is the only permitted
			// difference, so assert it precisely rather than skipping.
			if wantErr == nil && (want > Max || want < -Max) {
				if !errors.Is(gotErr, ErrOverflow) {
					t.Fatalf("Parse(%q) = (%v, %v), want ErrOverflow (stdlib gave %v, past Max)", in, got, gotErr, want)
				}
				return
			}
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("Parse(%q) err = %v, time.ParseDuration err = %v", in, gotErr, wantErr)
			}
			if wantErr == nil && got != want {
				t.Fatalf("Parse(%q) = %v, time.ParseDuration = %v", in, got, want)
			}
		})
	}
}

func TestParseRejectsWhatStdlibRejects(t *testing.T) {
	for _, in := range []string{"", "1", "h", "-", "+", "1x", "abc", "1..5s", "s", "1h-30m"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded, want an error", in)
		}
	}
}

func TestExtendedUnits(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"1d", 24 * time.Hour},
		{"30d", 720 * time.Hour},
		{"1w", 168 * time.Hour},
		{"2w", 336 * time.Hour},
		{"1mon", 720 * time.Hour},
		{"6mon", 4320 * time.Hour},
		{"1y", 8760 * time.Hour},
		{"-30d", -720 * time.Hour},
		{"+1d", 24 * time.Hour},
		{"1w2d", 216 * time.Hour},
		{"1d12h", 36 * time.Hour},
		{"1y1mon1w1d1h1m1s", 8760*time.Hour + 720*time.Hour + 168*time.Hour + 24*time.Hour + time.Hour + time.Minute + time.Second},
		{"1d0.5h", 24*time.Hour + 30*time.Minute},
	} {
		got, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// "m" is minutes and must stay minutes: "mon" has to win the longest-match
// without stealing the minute suffix. This is the single most likely way to
// silently break every existing config.
func TestMinutesAreNotMonths(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"1m", time.Minute},
		{"15m", 15 * time.Minute},
		{"1mon", Month},
		{"1m30s", time.Minute + 30*time.Second},
		{"1mon30m", Month + 30*time.Minute},
		{"1ms", time.Millisecond},
	} {
		got, err := Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q) error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A TTL <= 0 is stored as "no expiry", so an overflowing block TTL would
// become a permanent block. No positive literal may ever produce one.
func TestOverflowIsRejectedNotWrapped(t *testing.T) {
	for _, in := range []string{
		"101y", "1000y", "99999999999999999999y", "10000mon", "50000w",
		"100y1d", "36501d", "9223372036854775807y",
	} {
		got, err := Parse(in)
		if err == nil {
			t.Errorf("Parse(%q) = %v, want an overflow error", in, got)
			continue
		}
		if !errors.Is(err, ErrOverflow) {
			t.Errorf("Parse(%q) error = %v, want ErrOverflow", in, err)
		}
	}
	// The boundary itself is accepted.
	if got, err := Parse("100y"); err != nil || got != Max {
		t.Errorf("Parse(\"100y\") = (%v, %v), want (%v, nil)", got, err, Max)
	}
}

// Property: no positive input may yield a non-positive duration, which is the
// exact condition that turns a TTL into a permanent block.
func TestNoPositiveInputYieldsNonPositive(t *testing.T) {
	for _, unit := range []string{"ns", "us", "ms", "s", "m", "h", "d", "w", "mon", "y"} {
		for _, n := range []int{1, 2, 7, 30, 99, 365, 1000, 100000, 1000000000} {
			in := fmt.Sprintf("%d%s", n, unit)
			got, err := Parse(in)
			if err != nil {
				continue // rejected is fine; wrapped is not
			}
			if got <= 0 {
				t.Fatalf("Parse(%q) = %v: a positive literal produced a non-positive duration", in, got)
			}
		}
	}
}

func TestFractionalExtendedUnitsRejectedWithGuidance(t *testing.T) {
	for _, in := range []string{"1.5d", "0.5w", "2.5mon", "1.5y"} {
		_, err := Parse(in)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded, want a rejection", in)
		}
		if !strings.Contains(err.Error(), "36h") {
			t.Errorf("Parse(%q) error %q should suggest using a smaller unit", in, err)
		}
	}
}

func TestFormat(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want string
	}{
		{0, "0s"},
		{24 * time.Hour, "1d"},
		{720 * time.Hour, "1mon"}, // 30d exactly; not a whole year, so mon wins
		{8760 * time.Hour, "1y"},
		{168 * time.Hour, "1w"},
		{90 * time.Minute, "1h30m0s"},
		{-24 * time.Hour, "-1d"},
		{Max, "100y"},
	} {
		if got := Format(tc.in); got != tc.want {
			t.Errorf("Format(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
