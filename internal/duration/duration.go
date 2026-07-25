// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package duration parses Go duration strings extended with the calendar-ish
// units operators actually reach for: days, weeks, months and years.
//
// time.ParseDuration stops at hours, so a 30-day block had to be written
// "720h" and guardian.yaml could not say "block_ttl: 30d" at all. Every
// duration in the config and in the admin API goes through Parse here, so the
// two accept exactly the same syntax.
package duration

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// The extended units. Days are a fixed 24h: this is a TTL length, not a
// wall-clock calendar offset, so it deliberately does not follow DST. Months
// and years are fixed too, at 30 and 365 days, because a TTL has no anchor
// date from which to count real months or leap days. Anything needing true
// calendar arithmetic should not be expressed as a duration in the first
// place.
const (
	Day   = 24 * time.Hour
	Week  = 7 * Day
	Month = 30 * Day
	Year  = 365 * Day
)

// Max is the largest duration Parse accepts.
//
// It exists to make overflow structurally impossible rather than merely
// detected. time.Duration is int64 nanoseconds and wraps negative somewhere
// past 292 years, and a negative TTL is not a small error here: Store treats
// ttl <= 0 as "no expiry", so a wrapped block TTL becomes a permanent block
// that only an admin can lift (see the hardMaxBlockTTL note in
// core/scoreboard.go). A century is far below the wrap and far above anything
// legitimate. Block TTLs are separately capped at core.MaxStateTTL (1y).
const Max = 100 * Year

// ErrOverflow is returned for a magnitude beyond Max.
var ErrOverflow = errors.New("duration exceeds the maximum")

// extended units, longest suffix first so "mon" is matched before "m".
// Order is load-bearing: "m" is minutes and must stay minutes.
var extended = []struct {
	suffix string
	mult   time.Duration
}{
	{"mon", Month},
	{"d", Day},
	{"w", Week},
	{"y", Year},
}

// stdUnits are the suffixes time.ParseDuration owns. Listed longest-first for
// the same reason, and used only to recognise a term, never to evaluate one.
var stdUnits = []string{"ns", "us", "µs", "μs", "ms", "s", "m", "h"}

// Parse is time.ParseDuration extended with d, w, mon and y.
//
// A string containing no extended unit is handed to time.ParseDuration
// verbatim, so every input the stdlib accepts parses to the identical value by
// construction: signed, fractional and multi-unit forms all behave exactly as
// before. Extended units compose the same way ("1w2d12h"), but take whole
// numbers only, because a fractional month is not a thing anyone means. The
// one added restriction is Max, which is well beyond any real config.
func Parse(s string) (time.Duration, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("invalid duration %q: empty", s)
	}

	body := trimmed
	neg := false
	switch body[0] {
	case '-':
		neg, body = true, body[1:]
	case '+':
		body = body[1:]
	}

	// Fast path and compatibility guarantee in one: no extended unit means
	// this is a plain Go duration, so let the stdlib own it entirely.
	if !hasExtendedUnit(body) {
		d, err := time.ParseDuration(trimmed)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		if d > Max || d < -Max {
			return 0, fmt.Errorf("invalid duration %q: %w of %s", s, ErrOverflow, Format(Max))
		}
		return d, nil
	}

	// Mixed form: sum the extended terms exactly in int64 and let the stdlib
	// evaluate whatever standard terms are left, so no arithmetic here can
	// disagree with it.
	var total time.Duration
	var std strings.Builder
	for body != "" {
		digits, rest := leadingDigits(body)
		if digits == "" {
			return 0, fmt.Errorf("invalid duration %q: missing number before %q", s, unitOf(body))
		}
		if suffix, mult, ok := leadingExtended(rest); ok {
			n, err := parseUint(digits)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q: %w", s, err)
			}
			term, err := mulChecked(n, mult)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q: %w of %s", s, err, Format(Max))
			}
			total, err = addChecked(total, term)
			if err != nil {
				return 0, fmt.Errorf("invalid duration %q: %w of %s", s, err, Format(Max))
			}
			body = rest[len(suffix):]
			continue
		}
		suffix, ok := leadingStd(rest)
		if !ok {
			return 0, fmt.Errorf("invalid duration %q: unknown unit %q", s, unitOf(rest))
		}
		// A fraction is legal in a standard term; the stdlib will see the
		// whole term including its digits, so it validates and evaluates it.
		std.WriteString(digits)
		std.WriteString(suffix)
		body = rest[len(suffix):]
	}

	if std.Len() > 0 {
		d, err := time.ParseDuration(std.String())
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		total, err = addChecked(total, d)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w of %s", s, err, Format(Max))
		}
	}

	if neg {
		total = -total
	}
	return total, nil
}

// hasExtendedUnit reports whether s contains a d/w/mon/y term. It looks for a
// unit letter immediately after a digit or dot so that the "s" in "ms" or a
// stray character cannot be mistaken for one.
func hasExtendedUnit(s string) bool {
	for i := 1; i < len(s); i++ {
		prev := s[i-1]
		if !(prev >= '0' && prev <= '9') && prev != '.' {
			continue
		}
		switch s[i] {
		case 'd', 'w', 'y':
			return true
		case 'm':
			if strings.HasPrefix(s[i:], "mon") {
				return true
			}
		}
	}
	return false
}

// leadingDigits consumes an optional decimal number (digits with at most one
// dot) and returns it verbatim with the remainder.
func leadingDigits(s string) (num, rest string) {
	i, dot, digits := 0, false, false
	for ; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			digits = true
			continue
		}
		if c == '.' && !dot {
			dot = true
			continue
		}
		break
	}
	if !digits {
		return "", s
	}
	return s[:i], s[i:]
}

func leadingExtended(s string) (suffix string, mult time.Duration, ok bool) {
	for _, u := range extended {
		if strings.HasPrefix(s, u.suffix) {
			return u.suffix, u.mult, true
		}
	}
	return "", 0, false
}

func leadingStd(s string) (suffix string, ok bool) {
	for _, u := range stdUnits {
		if strings.HasPrefix(s, u) {
			return u, true
		}
	}
	return "", false
}

// parseUint rejects the fractional forms the extended units do not take, with
// an error that says what to write instead.
func parseUint(digits string) (int64, error) {
	if strings.Contains(digits, ".") {
		return 0, fmt.Errorf("fractional value %q is not allowed on d, w, mon or y: use a smaller unit (for example 36h, not 1.5d)", digits)
	}
	var n int64
	for i := 0; i < len(digits); i++ {
		d := int64(digits[i] - '0')
		if n > (int64(Max)/int64(time.Nanosecond))/10 {
			return 0, ErrOverflow
		}
		n = n*10 + d
	}
	return n, nil
}

func mulChecked(n int64, mult time.Duration) (time.Duration, error) {
	if n != 0 && n > int64(Max)/int64(mult) {
		return 0, ErrOverflow
	}
	return time.Duration(n) * mult, nil
}

func addChecked(a, b time.Duration) (time.Duration, error) {
	sum := a + b
	// Both operands are non-negative here (the sign is applied once at the
	// end), so a decrease can only mean wraparound.
	if sum < a || sum > Max {
		return 0, ErrOverflow
	}
	return sum, nil
}

// unitOf extracts the offending unit text for an error message: everything up
// to the next digit, sign or dot.
func unitOf(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+' {
			return s[:i]
		}
	}
	return s
}

// Format renders d preferring the largest extended unit that divides it
// exactly, for error messages and docs. Config round-tripping still marshals
// through time.Duration.String(), so a config written "30d" reads back
// "720h0m0s".
func Format(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	sign := ""
	if d < 0 {
		sign, d = "-", -d
	}
	for _, u := range []struct {
		mult time.Duration
		name string
	}{{Year, "y"}, {Month, "mon"}, {Week, "w"}, {Day, "d"}} {
		if d%u.mult == 0 {
			return fmt.Sprintf("%s%d%s", sign, d/u.mult, u.name)
		}
	}
	return sign + d.String()
}
