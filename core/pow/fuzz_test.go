// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// FuzzRedeem drives the redeem path with arbitrary challenge IDs and nonces
// against a real (issued) challenge in the store. Redeem parses a
// client-controlled challenge ID and nonce and decodes the stored record;
// a hostile ID/nonce must yield an error, never a panic or a spurious mint.
func FuzzRedeem(f *testing.F) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ctx := context.Background()

	f.Add("", "")
	f.Add("00000000000000000000000000000000", "0")
	f.Add("../../etc/passwd", "\x00")
	f.Add("not-hex-but-32-characters-long!!", "999999999999999999999")

	f.Fuzz(func(t *testing.T, challengeID, nonce string) {
		// Fresh store + manager per input: issue one real challenge so the
		// redeem path has something to look up, then attack it with the
		// fuzzed ID/nonce.
		st := store.NewMemory()
		defer st.Close()
		m := NewManager(key, st)
		if _, err := m.Issue(ctx, "fuzz.test", "203.0.113.7", "/x", 8, time.Minute, true); err != nil {
			t.Fatalf("issue: %v", err)
		}

		req := &RedeemRequest{
			ChallengeID:  challengeID,
			Nonce:        nonce,
			Host:         "fuzz.test",
			IP:           "203.0.113.7",
			UserAgent:    "curl/8",
			TokenTTL:     time.Hour,
			ChallengeTTL: time.Minute,
		}
		// Any panic here is the finding; a returned error is expected.
		_, _ = m.Redeem(ctx, req)
	})
}

// FuzzRedeemRecord fuzzes compact stored records directly: a non-compact,
// truncated, unknown-version or hostile record must not panic the decoder or
// Redeem. Defence in depth: the store is trusted, but a shared Redis could hold
// a value written by a different or older version.
func FuzzRedeemRecord(f *testing.F) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ctx := context.Background()

	f.Add([]byte(`{"state":"issued","host":"fuzz.test","ip":"203.0.113.7","challenge":"ab","difficulty":8,"nojs":true}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))
	f.Add([]byte("AGCR\x02"))
	var buf bytes.Buffer
	encoded, err := encodeChallengeRecord(&buf, &record{
		State: recordStateIssued, Host: "fuzz.test", IP: "203.0.113.7",
		ChallengeDigest: sha256.Sum256([]byte("fuzz challenge")),
		Difficulty:      8, URI: "/x", IssuedAt: time.Now().UnixMilli(),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bytes.Clone(encoded))

	f.Fuzz(func(t *testing.T, rec []byte) {
		st := store.NewMemory()
		defer st.Close()
		m := NewManager(key, st)
		// Plant the fuzzed bytes as a challenge record, then redeem it.
		id := "0123456789abcdef0123456789abcdef"
		if err := st.Set(ctx, challengeKey(id), rec, time.Minute); err != nil {
			t.Skip()
		}
		req := &RedeemRequest{
			ChallengeID: id, Nonce: "0",
			Host: "fuzz.test", IP: "203.0.113.7", UserAgent: "curl/8",
			TokenTTL: time.Hour, ChallengeTTL: time.Minute,
		}
		_, _ = m.Redeem(ctx, req)

		// Also drive the version dispatch and decoder directly.
		_, _ = decodeChallengeRecord(rec)
	})
}
