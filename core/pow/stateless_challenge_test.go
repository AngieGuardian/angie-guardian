// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package pow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// countingStore counts writes and can force CAS failures, to prove stateless
// issuance is store-free and that a failed single-spend still mints.
type countingStore struct {
	store.Store
	writes  atomic.Int64
	failCAS bool
}

func (s *countingStore) Set(ctx context.Context, key string, v []byte, ttl time.Duration) error {
	s.writes.Add(1)
	return s.Store.Set(ctx, key, v, ttl)
}

func (s *countingStore) CompareAndSwap(ctx context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	s.writes.Add(1)
	if s.failCAS {
		return false, errors.New("store down")
	}
	return s.Store.CompareAndSwap(ctx, key, old, new, ttl)
}

func TestStatelessRoundTrip(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	ch, err := m.IssueStateless("Example.test", "203.0.113.7", "/page?x=1", 8, false)
	if err != nil {
		t.Fatal(err)
	}
	if !IsStatelessID(ch.ID) || !strings.HasPrefix(ch.ID, "s1.") {
		t.Fatalf("id %q is not a stateless id", ch.ID)
	}
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "example.test", IP: "203.0.113.7", UserAgent: "Mozilla/5.0",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if res.Token == "" || res.RedirectURI != "/page?x=1" || res.SoftError != nil {
		t.Fatalf("bad result: %+v", res)
	}
	// A stateless challenge carries its own difficulty and issue time in the
	// MAC-verified payload, so a solve redeemed during a store outage is as
	// attributable as a stateful one.
	if res.Difficulty != 8 {
		t.Errorf("difficulty = %d, want 8", res.Difficulty)
	}
	if res.IssuedAt.IsZero() || time.Since(res.IssuedAt) > time.Minute {
		t.Errorf("issued_at = %v, want the issue time just now", res.IssuedAt)
	}
	// The minted token verifies at the embedded difficulty.
	if err := m.VerifyToken(res.Token, "example.test", "203.0.113.7", "Mozilla/5.0", 8, time.Hour); err != nil {
		t.Fatalf("token does not verify: %v", err)
	}
}

func TestStatelessIssuesNoStoreWrite(t *testing.T) {
	m := testManager(t)
	cs := &countingStore{Store: m.store}
	m.store = cs
	if _, err := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false); err != nil {
		t.Fatal(err)
	}
	if cs.writes.Load() != 0 {
		t.Fatalf("stateless issuance performed %d store writes, want 0", cs.writes.Load())
	}
}

func TestStatelessPayloadUsesJSONV2Contract(t *testing.T) {
	p := &statelessPayload{
		V: 1, Host: "example.test", IP: "203.0.113.7", Bits: 8,
		URI: "/page?x=1", TS: 1234, Rand: "00112233445566778899aabb",
	}
	got, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"h":"example.test","i":"203.0.113.7","d":8,"u":"/page?x=1","n":0,"t":1234,"r":"00112233445566778899aabb"}`
	if string(got) != want {
		t.Fatalf("payload = %s\nwant    = %s", got, want)
	}
	if bytes.Contains(got, []byte(`"m":0`)) || bytes.Contains(got, []byte(`"p":0`)) {
		t.Fatalf("zero Argon2 fields leaked into SHA payload: %s", got)
	}
}

func TestEncodeStatelessChallengeMatchesReference(t *testing.T) {
	m := testManager(t)
	secret := m.issuingSecret()
	payloads := [][]byte{
		[]byte(`{"v":1,"h":"example.test","i":"203.0.113.7","d":8,"u":"/","n":0,"t":1234,"r":"00112233445566778899aabb"}`),
		[]byte(`{"v":1,"h":"escaped\\host","i":"2001:db8::1","d":32,"u":"/page?x=<&y=\\\"","n":1,"t":9223372036854775807,"r":"ffeeddccbbaa998877665544"}`),
		bytes.Repeat([]byte("long-payload-"), 100),
	}
	for _, size := range []int{0, 1, 2, 3, 767, 768, 769, 770, 1536, 1537} {
		payloads = append(payloads, bytes.Repeat([]byte{'x'}, size))
	}
	for _, payload := range payloads {
		gotID, gotSolve := m.encodeStatelessChallenge(secret, payload)
		mac := statelessMAC(secret, payload)
		wantID := statelessPrefix + b64.EncodeToString(payload) + "." + b64.EncodeToString(mac)
		wantSolve := statelessSolve(secret, payload)
		if gotID != wantID {
			t.Fatalf("ID differs from reference\nwant %q\n got %q", wantID, gotID)
		}
		if gotSolve != wantSolve {
			t.Fatalf("solve differs from reference\nwant %q\n got %q", wantSolve, gotSolve)
		}
	}
}

func TestStatelessConcurrentIssuanceRoundTrips(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	const workers = 16
	const issuesPerWorker = 25

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for worker := range workers {
		wg.Go(func() {
			ip := "203.0.113." + strconv.Itoa(worker+1)
			for range issuesPerWorker {
				ch, err := m.IssueStateless("concurrent.test", ip, "/page?x=1", 0, false)
				if err != nil {
					errs <- err
					return
				}
				if _, err := m.Redeem(ctx, &RedeemRequest{
					ChallengeID: ch.ID, Nonce: "0", Host: "concurrent.test", IP: ip,
					UserAgent: "test", TokenTTL: time.Hour, ChallengeTTL: time.Minute,
				}); err != nil {
					errs <- err
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestStatelessMACTamperRejected(t *testing.T) {
	m := testManager(t)
	ch, err := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the payload segment.
	parts := strings.SplitN(ch.ID, ".", 3)
	tampered := parts[0] + "." + flipChar(parts[1]) + "." + parts[2]
	_, err = m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: tampered, Nonce: "0",
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("tampered payload err = %v, want ErrChallengeUnknown", err)
	}
}

func TestStatelessBindingMismatch(t *testing.T) {
	m := testManager(t)
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	_, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.99", UserAgent: "x", // wrong IP
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("wrong-IP err = %v, want ErrBindingMismatch", err)
	}
}

func TestStatelessExpiryAndSkew(t *testing.T) {
	m := testManager(t)
	now := time.Now()
	m.now = func() time.Time { return now }
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	nonce := solve(t, ch.Challenge, 8)

	// Past the challenge TTL: rejected.
	m.now = func() time.Time { return now.Add(31 * time.Minute) }
	_, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: nonce,
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("expired err = %v, want ErrChallengeUnknown", err)
	}

	// Issued far in the "future" (beyond skew): rejected.
	m.now = func() time.Time { return now.Add(-2 * time.Minute) }
	_, err = m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: nonce,
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("future-skew err = %v, want ErrChallengeUnknown", err)
	}
}

func TestStatelessBadSolution(t *testing.T) {
	m := testManager(t)
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 12, false)
	// The nonce must be one that provably fails the difficulty, not one that
	// merely looks wrong: a stateless challenge string is randomized per
	// issuance, so a hardcoded nonce solves it by luck about once every 2^12
	// runs and the test fails in CI for no reason. unsolve searches for a
	// nonce whose hash is definitively short of the required leading zeros.
	_, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: unsolve(t, ch.Challenge, 12),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrBadSolution) {
		t.Fatalf("bad solution err = %v, want ErrBadSolution", err)
	}
}

func TestStatelessReplayRejected(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	req := &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	}
	if _, err := m.Redeem(ctx, req); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	if _, err := m.Redeem(ctx, req); !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("replay err = %v, want ErrChallengeUnknown", err)
	}
}

func TestStatelessSpendCASFailureStillMints(t *testing.T) {
	m := testManager(t)
	cs := &countingStore{Store: m.store, failCAS: true}
	m.store = cs
	ch, _ := m.IssueStateless("a.test", "203.0.113.7", "/", 8, false)
	res, err := m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("store-down redeem should fail open, got err %v", err)
	}
	if res.Token == "" || res.SoftError == nil {
		t.Fatalf("expected a minted token with a SoftError, got %+v", res)
	}
	// The local fallback cache still enforces single-spend within this process,
	// including attempts to mint a differently fingerprinted token by changing
	// the User-Agent while keeping the challenge's bound IP.
	_, err = m.Redeem(context.Background(), &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "different-UA",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if !errors.Is(err, ErrChallengeUnknown) {
		t.Fatalf("store-down local replay err = %v, want ErrChallengeUnknown", err)
	}
}

func TestStatefulStillRedeemsAlongsideStateless(t *testing.T) {
	// The 32-hex stateful path must keep working after the dispatch change.
	m := testManager(t)
	ctx := context.Background()
	ch, err := m.Issue(ctx, "a.test", "203.0.113.7", "/", 8, 30*time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: solve(t, ch.Challenge, 8),
		Host: "a.test", IP: "203.0.113.7", UserAgent: "x",
		TokenTTL: time.Hour, ChallengeTTL: 30 * time.Minute,
	})
	if err != nil || res.Token == "" {
		t.Fatalf("stateful redeem broke: %v / %+v", err, res)
	}
}

func flipChar(s string) string {
	b := []byte(s)
	if len(b) == 0 {
		return "x"
	}
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

// TestStatelessSpentMarkerOutlivesTheSkewAllowance pins the single-spend
// guarantee against the clock tolerance the same function grants.
//
// redeemStateless decides freshness by comparing the challenge's authenticated
// timestamp against THIS instance's clock, with statelessSkew of slack in
// either direction so replicas sharing a key can redeem each other's
// challenges. The spent marker is what stops a second redemption, and it lives
// in the store under a TTL. If that TTL is measured on the local clock alone it
// can lapse while a replica running statelessSkew behind still considers the
// challenge fresh, and one solve mints two tokens: redeem on the instance whose
// clock is ahead, wait out the short marker, redeem again on the one behind.
// Reproduced end to end with two managers on one store before this was fixed.
//
// The invariant is asserted directly rather than by racing a real store expiry:
// whatever is left of challenge_ttl, the marker must still cover the full skew
// window on top of it. The clock is driven to the last instant of the challenge
// window, which is where the margin is thinnest and the bug appeared.
func TestStatelessSpentMarkerOutlivesTheSkewAllowance(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	t.Cleanup(func() { st.Close() })
	key, err := LoadOrCreateKey(filepath.Join(t.TempDir(), "ed25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(key, st)

	const host, ip, ua = "x.test", "198.51.100.9", "Mozilla"
	const challengeTTL = 30 * time.Minute

	issuedAt := time.Now()
	m.now = func() time.Time { return issuedAt }
	ch, err := m.IssueStateless(host, ip, "/", 4, false)
	if err != nil {
		t.Fatal(err)
	}
	nonce := solveStatelessNonce(t, ch.Challenge, 4)

	// Redeem in the final moment of the challenge's life, so the residual
	// window is as small as it can be while still being accepted.
	m.now = func() time.Time { return issuedAt.Add(challengeTTL - time.Millisecond) }
	if _, err := m.Redeem(ctx, &RedeemRequest{
		ChallengeID: ch.ID, Nonce: nonce, Host: host, IP: ip, UserAgent: ua,
		TokenTTL: time.Hour, ChallengeTTL: challengeTTL,
	}); err != nil {
		t.Fatalf("redeem: %v", err)
	}

	kvs, err := st.Scan(ctx, "spent1:")
	if err != nil {
		t.Fatal(err)
	}
	if len(kvs) != 1 {
		t.Fatalf("found %d spent markers, want exactly 1", len(kvs))
	}
	// Against the real clock, which is what the store expires on. The manager's
	// clock is driven, but the store's is not, so the wall time this test spends
	// between the redeem and this read comes off the measured remainder: allow a
	// second of it. Without the fix the marker lasts a millisecond, so the
	// tolerance cannot mask the defect.
	got := time.Until(kvs[0].ExpiresAt)
	if got < statelessSkew-time.Second {
		t.Errorf("spent marker expires in %v, less than the %v of clock skew redemption tolerates: "+
			"a replica that far behind still accepts this challenge, so the same solve mints a second token",
			got.Round(time.Millisecond), statelessSkew)
	}
}

// solveStatelessNonce finds a nonce meeting difficulty, the honest client's job.
func solveStatelessNonce(t *testing.T, challenge string, difficulty int) string {
	t.Helper()
	for n := range 1_000_000 {
		nonce := strconv.Itoa(n)
		sum := sha256.Sum256([]byte(challenge + nonce))
		if leadingZeroBits(sum[:]) >= difficulty {
			return nonce
		}
	}
	t.Fatal("no solution found")
	return ""
}
