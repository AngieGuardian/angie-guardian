// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"time"

	"github.com/melroy89/angie-guardian/core/enforce"
	"github.com/melroy89/angie-guardian/core/store"
)

// blockKeyPrefix namespaces active behavioural blocks in the store; the
// admin API and enforcement reconciler enumerate its dedicated store index.
const blockKeyPrefix = "block:"

// canonIP reduces every textual form of the same address (mixed case,
// expanded zeros, IPv4-mapped IPv6 as produced by a dual-stack listener) to
// one canonical string, so all scoreboard keys agree on the client identity.
// Unparseable input passes through verbatim (fail-open, matching the
// pipeline's stance on a garbage RemoteAddr).
func canonIP(ip string) string {
	if addr, err := netip.ParseAddr(ip); err == nil {
		return addr.Unmap().String()
	}
	return ip
}

// BlockKey is the store key holding an active behavioural block for an IP.
// Written by the scoreboard, read by the behaviour-block pipeline stage.
//
// It is on the hot path for a read-through mirror (one lookup per request on a
// shared store), so the canonical address is appended straight into a
// stack-sized scratch array rather than formatted into its own string and then
// concatenated: 45 bytes covers the longest textual IPv6 address, so only the
// returned string is ever allocated.
func BlockKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return blockKeyPrefix + ip // fail-open, matching canonIP
	}
	var buf [len(blockKeyPrefix) + 48]byte
	b := append(buf[:0], blockKeyPrefix...)
	b = addr.Unmap().AppendTo(b)
	return string(b)
}

func blockCountKey(ip string) string { return "blkct:" + ip }

// unblockHoldKey suppresses automatic scoring and blocking of an IP while an
// unblock of it is recent. Only its presence matters, and it is the store that
// expires it, so no instance has to compare its own clock against another's.
func unblockHoldKey(ip string) string { return "unblk:" + ip }

// unblockGenKey identifies the most recent unblock of an IP. The value carries
// no meaning of its own and is never interpreted, only compared: a writer asks
// whether it changed while it was working, which is a question no instance's
// clock takes part in. Wall clocks on two instances do not agree, and a lagging
// peer's later unblock would carry an earlier time.
func unblockGenKey(ip string) string { return "unblkgen:" + ip }

// unblockHoldWindow is how long an unblock suppresses automatic scoring and
// blocking of the same IP.
//
// A reset cannot be made atomic against concurrent scorers with reads and
// deletes alone. The hold suppresses the ordinary case cheaply; generation-
// scoped event keys and the final atomic unblock commit settle writers that
// were admitted before it existed or after it expired.
//
// Correctness therefore does not require this finite TTL to cover unbounded
// reset work. The final commit refreshes it, and what remains for the TTL to
// cover is a request admitted immediately after the unblock returns. Two
// seconds is comfortably longer than such a request's whole lifetime and short
// enough to be nothing an operator has to plan around.
const unblockHoldWindow = 2 * time.Second

// unblockGenRetention is how long the generation survives, which is a much
// longer and entirely separate question from how long an unblock suppresses
// blocking.
//
// A block writer is admitted by one read of the generation and commits its
// write some time later. Nothing bounds that gap, so CommitBlock compares the
// generation inside the same store transaction that writes the block and
// offense. Event counters carry the generation in their key, making a late
// increment obsolete rather than something that has to be compensated.
//
// Every unblock rewrites the generation rather than incrementing it, so this
// is a full retention from the unblock in question, not from whichever earlier
// unblock happened to create the key.
//
// A day is orders of magnitude beyond any in-flight write (whose request
// context dies long before) while still bounding the keyspace: one small key
// per unblocked IP per day, and unblocks are an operator action.
const unblockGenRetention = 24 * time.Hour

// Scoreboard counts bad-behaviour events per IP in time-bucketed windows and
// places TTL'd blocks when a per-domain threshold is crossed. Only discrete
// bad events are counted (WAF rule hits, PoW failures, tamper, honeypot):
// they are rare, so a store write per event is affordable. It is inherently
// stateful (needs the shared store), so it lives with the sidecar, not in the
// store-free stateless package.
type Scoreboard struct {
	store    store.Store
	log      *slog.Logger
	now      func() time.Time
	enforcer *enforce.Manager // nil-safe; mirrors every block change
	// unblockHold is unblockHoldWindow, overridable so a test can run the
	// scoring path without waiting the window out. Zero disables the unblock
	// coordination entirely.
	unblockHold time.Duration
}

func NewScoreboard(st store.Store, log *slog.Logger) *Scoreboard {
	return &Scoreboard{store: st, log: log, now: time.Now, unblockHold: unblockHoldWindow}
}

// HoldUnblock records an unblock of an IP. For unblockHoldWindow afterwards,
// this scoreboard (and every other instance sharing the store) neither counts
// behaviour events for the IP nor places an automatic block on it. The
// generation it writes outlives that window by unblockGenRetention, so a block
// writer admitted before the unblock can still recognise, whenever it finally
// gets to write, that its block belongs to a decision the operator has since
// reversed.
//
// The two writes are ordered, and so are the two reads that pair with them in
// Block: the hold is written first and read second, the generation written
// second and read first. That is what leaves no gap. A writer that misses the
// hold (read before it was written) must have read the generation earlier
// still, so it sees the change on the way out; a writer that misses the change
// (read after it) must be reading the hold later still, so it is suppressed
// before it writes anything.
//
// Call it before touching any of the state the unblock resets. The final
// CommitUnblock publishes another generation atomically with the authoritative
// block/backoff removal. That second boundary, rather than assuming this
// finite hold remained continuously live through unbounded store work, is what
// makes writes admitted during a slow reset stale.
//
// Admin blocks are deliberately not gated by it. They do not go through this
// scoreboard, so an operator who unblocks and immediately blocks by hand gets
// what they asked for.
func (s *Scoreboard) HoldUnblock(ctx context.Context, ip string) error {
	if s.unblockHold <= 0 {
		return nil
	}
	ip = canonIP(ip)
	if err := s.store.Set(ctx, unblockHoldKey(ip), []byte("1"), s.unblockHold); err != nil {
		return err
	}
	// Set, not Incr: an increment preserves the key's original expiry, so an
	// IP unblocked twice near the end of a retention period would get a
	// generation about to vanish, and a writer that outlived it would find
	// nothing to compare against. Every unblock's generation is good for a
	// full retention from that unblock.
	return s.store.Set(ctx, unblockGenKey(ip), unblockGenValue(), unblockGenRetention)
}

// unblockGenValue is a fresh generation: 128 random bits, rendered hex.
//
// It is a token rather than a counter because the only question asked of it is
// "did this change?", and a counter cannot answer that safely across an expiry
// (it restarts at 1, so a writer admitted at 1 an epoch ago reads 1 again and
// concludes nothing happened). It is not a timestamp because two instances do
// not agree on those. Nothing outside the process ever sees it, so it needs to
// be unlikely to repeat, not unguessable.
func unblockGenValue() []byte {
	var b [32]byte
	hi := strconv.AppendUint(b[:0], rand.Uint64(), 16)
	return strconv.AppendUint(hi, rand.Uint64(), 16)
}

// unblockToken reads the current generation for this (already canonical) IP.
// An absent key is the empty token: never having been unblocked is a definite
// generation. Store errors are returned because using an invented generation
// would let a conditional mutation commit against the wrong epoch.
func (s *Scoreboard) unblockToken(ctx context.Context, ip string) (string, error) {
	if s.unblockHold <= 0 {
		return "", nil
	}
	v, ok, err := s.store.Get(ctx, unblockGenKey(ip))
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	return string(v), nil
}

// notifyEnforcer feeds one block change to the enforcement offload. The ip
// string is what BlockKey stores; unparseable values (impossible from the
// Angie transport) just stay on the store-only path.
func (s *Scoreboard) notifyEnforcer(ip, reason string, ttl time.Duration, remove bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	s.enforcer.Notify(enforce.BlockEvent{IP: addr, Reason: reason, TTL: ttl, Remove: remove})
}

// notifyOwnedEnforcer publishes an automatic block only while the exact value
// committed by this writer is still authoritative. Manager serializes this
// validation with local remove/replacement notifications, so a delayed writer
// cannot re-add itself after an unblock or overwrite a newer mirror entry.
func (s *Scoreboard) notifyOwnedEnforcer(ctx context.Context, ip, reason string, ttl time.Duration, key string, owner []byte) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	s.enforcer.NotifyOwned(ctx,
		enforce.BlockEvent{IP: addr, Reason: reason, TTL: ttl},
		key, owner)
}

// eventBucket is the time-bucket index a behaviour counter for window falls
// in. Buckets are absolute slices of wall-clock time, so the index only ever
// climbs: once now moves past a bucket, that bucket is never incremented
// again. ResetEventCounters relies on that to know which keys still matter.
func eventBucket(now time.Time, window time.Duration) int64 {
	return now.Unix() / max(int64(window/time.Second), 1)
}

// eventKey is the store key for one IP's counter of evtype in one bucket and
// unblock generation. A final unblock rotates the generation, so a counter
// write admitted before that boundary can finish whenever it likes without
// refilling the current scoreboard.
func eventKey(evtype, ip, generation string, bucket int64) string {
	var buf [256]byte
	b := append(buf[:0], "ev:"...)
	b = append(b, evtype...)
	b = append(b, ':')
	b = append(b, ip...)
	b = append(b, ':')
	if generation == "" {
		b = append(b, '0')
	} else {
		b = append(b, 'g')
		b = append(b, generation...)
	}
	b = append(b, ':')
	b = strconv.AppendInt(b, bucket, 10)
	return string(b)
}

// RecordEvent counts one occurrence of evtype for ip within window. When the
// bucket reaches limit the IP is blocked. Returns whether a block was placed.
func (s *Scoreboard) RecordEvent(ctx context.Context, ip, evtype string, limit int, window, blockTTL, maxBlockTTL time.Duration) (bool, error) {
	if limit <= 0 || window <= 0 {
		return false, nil
	}
	// Canonicalize once so the event counter, backoff counter and block key
	// (via Block below) all see the same identity whatever textual form the
	// transport delivered.
	ip = canonIP(ip)
	generation, err := s.unblockToken(ctx, ip)
	if err != nil {
		return false, err
	}
	key := eventKey(evtype, ip, generation, eventBucket(s.now(), window))
	// The backend checks the hold in the same operation that increments the
	// generation-scoped counter. That preserves the hot
	// path's two exact-key store operations (generation read + guarded
	// increment) while making a final unblock an exact write boundary.
	result, err := s.store.CommitEvent(ctx, store.EventCommit{
		CounterKey: key,
		CounterTTL: 2 * window,
		HoldKey:    unblockHoldKey(ip),
	})
	if err != nil {
		return false, err
	}
	if !result.Committed || result.Value < int64(limit) {
		return false, nil
	}
	return true, s.Block(ctx, ip, "threshold:"+evtype, blockTTL, maxBlockTTL)
}

// hardMaxBlockTTL caps a block TTL when the config leaves maxBlockTTL
// unset/non-positive, so the exponential backoff can never overflow
// time.Duration (which wraps negative around ~2^63ns ≈ 292 years and, being
// ≤ 0, is stored as "no expiry" — a permanent, only-admin-removable block).
const hardMaxBlockTTL = 30 * 24 * time.Hour // 30 days

// Block places a behavioural block with exponential backoff: each block of
// the same IP within 24h doubles the TTL, capped at maxBlockTTL (or a hard
// 30-day ceiling when no cap is configured).
//
// Store.CommitBlock is the ownership boundary: in one backend
// transaction/script it validates the unblock generation and previous block,
// increments the offense, derives the TTL, and writes the new block. Thus no
// offense or block can land after an unblock that already reset it, and no
// writer can publish side effects for a block another writer has superseded.
func (s *Scoreboard) Block(ctx context.Context, ip, reason string, ttl, maxBlockTTL time.Duration) error {
	ip = canonIP(ip) // one backoff counter per client, whatever textual form arrived
	admitted, err := s.unblockToken(ctx, ip)
	if err != nil {
		return err
	}
	key := BlockKey(ip)
	prev, found, err := s.store.Get(ctx, key)
	if err != nil {
		return err
	}
	if !found {
		prev = nil // CAS spells "must still be absent" as a nil old value
	} else if prev == nil {
		prev = []byte{}
	}
	cap := maxBlockTTL
	if cap <= 0 {
		cap = hardMaxBlockTTL
	}
	if ttl <= 0 {
		ttl = time.Minute // degenerate base config; never let the block be permanent
	}
	mine := store.BlockValue(reason)
	var guard []byte
	if admitted != "" {
		guard = []byte(admitted)
	}
	committed, err := s.store.CommitBlock(ctx, store.BlockCommit{
		BlockKey:      key,
		ExpectedBlock: prev,
		NewBlock:      mine,
		BaseTTL:       ttl,
		MaxTTL:        cap,
		CounterKey:    blockCountKey(ip),
		CounterTTL:    24 * time.Hour,
		HoldKey:       unblockHoldKey(ip),
		GuardKey:      unblockGenKey(ip),
		GuardValue:    guard,
	})
	if err != nil {
		return err
	}
	if !committed.Committed {
		// Which comparison refused is the whole answer to "why was this IP not
		// blocked", and only the backend that ran them in one transaction can
		// tell them apart, so it reports it rather than leaving one message to
		// stand for three different situations.
		switch committed.Refusal {
		case store.BlockRefusalHold:
			s.log.Info("not blocking ip: an unblock of it is in flight", "ip", ip, "reason", reason)
		case store.BlockRefusalGeneration:
			s.log.Info("not blocking ip: an unblock of it completed while this block was being placed",
				"ip", ip, "reason", reason)
		case store.BlockRefusalBlock:
			s.log.Info("not blocking ip: a newer block is already in place", "ip", ip, "reason", reason)
		default:
			s.log.Info("not blocking ip", "ip", ip, "reason", reason, "refusal", committed.Refusal)
		}
		return nil
	}
	s.log.Info("blocking ip", "ip", ip, "reason", reason,
		"ttl", committed.TTL, "offenses", committed.Offenses)
	s.notifyOwnedEnforcer(ctx, ip, reason, committed.TTL, key, mine)
	return nil
}

// Unblock lifts an active block (admin action). It clears nothing else: the
// counters that produced the block are the caller's business, because which
// of them exist depends on config the scoreboard does not hold. Engine.UnblockIP
// is the operator-facing entry point and resets them; see the note there on
// why lifting the block on its own is not enough.
func (s *Scoreboard) Unblock(ctx context.Context, ip string) error {
	if err := s.store.Delete(ctx, BlockKey(ip)); err != nil {
		return err
	}
	s.notifyEnforcer(ip, "", 0, true)
	return nil
}

// CommitUnblock is the final atomic boundary of an operator unblock. Automatic
// blocks validate this generation in their own atomic commit, so one that
// raced the reset is either removed here or rejected afterwards together with
// its offense. The fresh hold covers work admitted immediately after return.
func (s *Scoreboard) CommitUnblock(ctx context.Context, ip string, resetBackoff bool) error {
	ip = canonIP(ip)
	if s.unblockHold <= 0 {
		if resetBackoff {
			if err := s.ResetBackoff(ctx, ip); err != nil {
				return err
			}
		}
		return s.Unblock(ctx, ip)
	}
	if err := s.store.CommitUnblock(ctx, store.UnblockCommit{
		HoldKey:       unblockHoldKey(ip),
		HoldValue:     []byte("1"),
		HoldTTL:       s.unblockHold,
		GenerationKey: unblockGenKey(ip),
		Generation:    unblockGenValue(),
		GenerationTTL: unblockGenRetention,
		BlockKey:      BlockKey(ip),
		CounterKey:    blockCountKey(ip),
		ResetBackoff:  resetBackoff,
	}); err != nil {
		return err
	}
	s.notifyEnforcer(ip, "", 0, true)
	return nil
}

// ResetEventCounters clears the per-IP behaviour counters that a threshold
// block was placed on, three keys per configured (event type, window). It
// returns how many keys it addressed and how many store deletes failed.
//
// The counters are not enumerable by prefix (the event type sits before the IP
// in the key), so the keys are reconstructed from the windows the caller
// resolved out of the running config. Three buckets, not one, because clock
// skew across instances sharing a store is symmetric: this process's live
// bucket is the one it will increment next, a peer running behind is still
// writing the previous bucket, and a peer running ahead has already been
// writing the next one, possibly all the way to the threshold. Leaving that
// next bucket would re-block the IP the moment this process's clock reaches
// it, which is the same "unblock did nothing" failure one window later.
//
// The counts are keys addressed, not keys that held a value: Store.Delete does
// not distinguish "removed" from "was not there", and an absent counter is
// exactly the state this wants.
func (s *Scoreboard) ResetEventCounters(ctx context.Context, ip, generation string, windows []BehaviourWindow) (keys, failed int) {
	ip = canonIP(ip) // RecordEvent canonicalizes before writing, so match it
	now := s.now()
	for _, w := range windows {
		if w.Event == "" || w.Window <= 0 {
			continue
		}
		bucket := eventBucket(now, w.Window)
		for _, b := range [...]int64{bucket - 1, bucket, bucket + 1} {
			keys++
			if err := s.store.Delete(ctx, eventKey(w.Event, ip, generation, b)); err != nil {
				failed++
			}
		}
	}
	return keys, failed
}

// ResetBackoff clears the repeat-offender counter behind Block's exponential
// backoff, so the next block of this IP starts at the base block_ttl again
// instead of a doubled one.
func (s *Scoreboard) ResetBackoff(ctx context.Context, ip string) error {
	return s.store.Delete(ctx, blockCountKey(canonIP(ip)))
}
