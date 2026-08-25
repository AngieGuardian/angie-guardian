// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/melroy89/angie-guardian/core/store"
)

func ordinaryChallengeRecord() record {
	return record{
		State: recordStateIssued, Host: "example.test", IP: "203.0.113.7",
		ChallengeDigest: sha256.Sum256([]byte("challenge digest")),
		Difficulty:      20, URI: "/page?x=1", NoJS: true, IssuedAt: 123456789,
	}
}

func TestCompactChallengeRecordRoundTrip(t *testing.T) {
	rec := ordinaryChallengeRecord()
	var buf bytes.Buffer
	encoded, err := encodeChallengeRecord(&buf, &rec)
	if err != nil {
		t.Fatal(err)
	}
	issued := bytes.Clone(encoded)
	if len(issued) != challengeRecordFixedSize+len(rec.Host)+len(rec.IP)+len(rec.URI) {
		t.Fatalf("encoded length = %d", len(issued))
	}
	if len(issued) > 110 {
		t.Fatalf("ordinary compact record = %d bytes, target is at most 110", len(issued))
	}
	got, err := decodeChallengeRecord(issued)
	if err != nil {
		t.Fatal(err)
	}
	if got != rec {
		t.Fatalf("decoded record differs\nwant %#v\n got %#v", rec, got)
	}

	// A compact spend must change only the state byte. The store CAS still
	// compares against every exact issued byte and writes a newly encoded value.
	rec.State = recordStateSpent
	spent, err := encodeChallengeRecord(&buf, &rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(spent) != len(issued) {
		t.Fatalf("spent length = %d, issued length = %d", len(spent), len(issued))
	}
	for i := range issued {
		if i == challengeRecordStateOffset {
			continue
		}
		if spent[i] != issued[i] {
			t.Fatalf("spending changed byte %d: %x -> %x", i, issued[i], spent[i])
		}
	}
	if issued[challengeRecordStateOffset] != challengeRecordStateIssued || spent[challengeRecordStateOffset] != challengeRecordStateSpent {
		t.Fatalf("state bytes = issued %d spent %d", issued[challengeRecordStateOffset], spent[challengeRecordStateOffset])
	}
}

func TestCompactChallengeRecordPreservesArbitraryBytes(t *testing.T) {
	rec := ordinaryChallengeRecord()
	rec.Host = "host\xff"
	rec.IP = "ip\xfe"
	rec.URI = "/raw\x80uri"
	var buf bytes.Buffer
	encoded, err := encodeChallengeRecord(&buf, &rec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeChallengeRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got != rec {
		t.Fatalf("arbitrary bytes changed\nwant %#v\n got %#v", rec, got)
	}
}

func TestJSONChallengeRecordIsRejectedAfterCompactMigration(t *testing.T) {
	raw := []byte(`{"state":"issued","host":"old.test","ip":"198.51.100.7","challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","difficulty":0,"uri":"/old","nojs":false,"issued_at":1}`)
	if _, err := decodeChallengeRecord(raw); !errors.Is(err, errChallengeRecord) {
		t.Fatalf("JSON decode error = %v, want errChallengeRecord", err)
	}

	m := testManager(t)
	ctx := context.Background()
	id := "01234567-89ab-4def-8123-456789abcdef"
	if err := m.store.Set(ctx, challengeKey(id), raw, time.Minute); err != nil {
		t.Fatal(err)
	}
	_, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: id, Nonce: "0", Host: "old.test", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("JSON record redemption = %v, want ErrChallengeUnknown", err)
	}
}

func TestCompactChallengeRecordSurvivesPebbleCrashReopen(t *testing.T) {
	const (
		crashDirEnv = "GUARDIAN_TEST_COMPACT_CRASH_DIR"
		crashKeyEnv = "GUARDIAN_TEST_COMPACT_CRASH_KEY"
	)
	ctx := context.Background()
	if dir := os.Getenv(crashDirEnv); dir != "" {
		key, err := LoadOrCreateKey(os.Getenv(crashKeyEnv))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		st, err := store.NewPebble(dir, store.PebbleOptions{Sync: true})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		ch, err := NewManager(key, st).Issue(ctx, "reopen.test", "198.51.100.7", "/after-restart", 0, time.Hour, false)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Fprint(os.Stdout, ch.ID)
		// Deliberately bypass Pebble.Close and every test defer. The sync write
		// must be recoverable after an abrupt process exit.
		os.Exit(0)
	}

	root := t.TempDir()
	dir := filepath.Join(root, "pebble")
	keyPath := filepath.Join(root, "ed25519.key")
	key, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCompactChallengeRecordSurvivesPebbleCrashReopen$")
	cmd.Env = append(os.Environ(), crashDirEnv+"="+dir, crashKeyEnv+"="+keyPath)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("crash writer: %v", err)
	}
	id := strings.TrimSpace(string(out))
	if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
		t.Fatalf("crash writer returned challenge ID %q", id)
	}

	open := func() (*store.Pebble, *Manager) {
		st, err := store.NewPebble(dir, store.PebbleOptions{Sync: true})
		if err != nil {
			t.Fatal(err)
		}
		return st, NewManager(key, st)
	}
	closeManagerStore := func(st *store.Pebble, manager *Manager) {
		// Issue and successful redemption update the asynchronous escalation
		// cache. Drain it before closing its backing store so repeated test runs
		// cannot leave a background writer racing the reopen boundary.
		if err := manager.counters.Flush(ctx); err != nil {
			t.Fatalf("flush challenge counters: %v", err)
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}

	st, redeemer := open()
	res, err := redeemer.Redeem(ctx, &RedeemRequest{
		ChallengeID: id, Nonce: "0", Host: "reopen.test", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.RedirectURI != "/after-restart" {
		t.Fatalf("redirect = %q", res.RedirectURI)
	}
	closeManagerStore(st, redeemer)

	st, afterSpend := open()
	defer closeManagerStore(st, afterSpend)
	if _, err := afterSpend.Redeem(ctx, &RedeemRequest{
		ChallengeID: id, Nonce: "0", Host: "reopen.test", IP: "198.51.100.7", UserAgent: "UA",
		TokenTTL: time.Hour, ChallengeTTL: time.Hour,
	}); !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("redeem after spent reopen = %v, want ErrChallengeUnknown", err)
	}
}

func TestCompactChallengeRecordRejectsMalformedInput(t *testing.T) {
	rec := ordinaryChallengeRecord()
	var buf bytes.Buffer
	valid, err := encodeChallengeRecord(&buf, &rec)
	if err != nil {
		t.Fatal(err)
	}
	valid = bytes.Clone(valid)

	unknownVersion := bytes.Clone(valid)
	unknownVersion[challengeRecordVersionOffset]++
	unknownState := bytes.Clone(valid)
	unknownState[challengeRecordStateOffset] = 0xff
	unknownFlags := bytes.Clone(valid)
	unknownFlags[6] = 0x80
	tests := map[string][]byte{
		"truncated version": challengeRecordMagic[:],
		"truncated body":    valid[:challengeRecordFixedSize-1],
		"unknown version":   unknownVersion,
		"unknown state":     unknownState,
		"unknown flags":     unknownFlags,
		"length short":      valid[:len(valid)-1],
		"length long":       append(bytes.Clone(valid), 0),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeChallengeRecord(raw); !errors.Is(err, errChallengeRecord) {
				t.Fatalf("decode error = %v, want errChallengeRecord", err)
			}
		})
	}
}

func TestCompactChallengeRecordEncodingBounds(t *testing.T) {
	tests := map[string]record{
		"unknown state": func() record { r := ordinaryChallengeRecord(); r.State = "future"; return r }(),
		"difficulty":    func() record { r := ordinaryChallengeRecord(); r.Difficulty = 256; return r }(),
	}
	for name, rec := range tests {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := encodeChallengeRecord(&buf, &rec); !errors.Is(err, errChallengeRecord) {
				t.Fatalf("encode error = %v, want errChallengeRecord", err)
			}
		})
	}

	rec := ordinaryChallengeRecord()
	// Guardian's HTTP server accepts up to 1 MiB of headers. The compact
	// format must not introduce the old uint16 boundary as a new rejection.
	rec.URI = strings.Repeat("x", 1<<20)
	var buf bytes.Buffer
	encoded, err := encodeChallengeRecord(&buf, &rec)
	if err != nil {
		t.Fatalf("one-megabyte field rejected: %v", err)
	}
	if _, err := decodeChallengeRecord(encoded); err != nil {
		t.Fatalf("maximum field did not round trip: %v", err)
	}
}
