// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Bolt is a persistent single-node Store backed by an embedded bbolt file.
// Values are stored as an 8-byte big-endian unix-nano expiry (0 = none)
// followed by the payload. Expired keys read as absent and are physically
// removed by a background sweeper.
type Bolt struct {
	db   *bolt.DB
	done chan struct{}
}

var boltBucket = []byte("guardian")

func NewBolt(path string) (*Bolt, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(boltBucket)
		return err
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	s := &Bolt{db: db, done: make(chan struct{})}
	go s.sweeper()
	return s, nil
}

func ttlDeadline(ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, nil
	}
	now := time.Now()
	deadline := now.Add(ttl).UnixNano()
	if deadline <= now.UnixNano() {
		return 0, fmt.Errorf("ttl %v exceeds bbolt's unix-nanosecond expiry range", ttl)
	}
	return deadline, nil
}

func encode(value []byte, ttl time.Duration) ([]byte, error) {
	deadline, err := ttlDeadline(ttl)
	if err != nil {
		return nil, err
	}
	return encodeAbs(value, deadline), nil
}

// encodeAbs stores value with an absolute unix-nano expiry (0 = no expiry).
func encodeAbs(value []byte, deadline int64) []byte {
	buf := make([]byte, 8+len(value))
	if deadline > 0 {
		binary.BigEndian.PutUint64(buf, uint64(deadline))
	}
	copy(buf[8:], value)
	return buf
}

// decode returns the payload, or ok=false if raw is missing or expired.
func decode(raw []byte, now time.Time) ([]byte, bool) {
	if len(raw) < 8 {
		return nil, false
	}
	exp := binary.BigEndian.Uint64(raw)
	if exp != 0 && now.UnixNano() > int64(exp) {
		return nil, false
	}
	return raw[8:], true
}

func (s *Bolt) sweeper() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			_ = s.db.Update(func(tx *bolt.Tx) error {
				c := tx.Bucket(boltBucket).Cursor()
				for k, v := c.First(); k != nil; k, v = c.Next() {
					if _, ok := decode(v, now); !ok {
						if err := c.Delete(); err != nil {
							return err
						}
					}
				}
				return nil
			})
		}
	}
}

func (s *Bolt) Get(_ context.Context, key string) ([]byte, bool, error) {
	var value []byte
	var ok bool
	err := s.db.View(func(tx *bolt.Tx) error {
		if v, hit := decode(tx.Bucket(boltBucket).Get([]byte(key)), time.Now()); hit {
			value = bytes.Clone(v)
			ok = true
		}
		return nil
	})
	return value, ok, err
}

// The mutating methods use db.Batch rather than db.Update: under concurrent
// writers (the auth hot path issues a challenge CAS per new client) Batch
// coalesces many calls into a few shared fsync'd commits, lifting throughput
// past bbolt's one-fsync-per-Update ceiling. Batch may invoke the fn more than
// once if a batch fails, so each closure recomputes its result from the tx and
// assigns the out-var fresh on every call (never appends/accumulates).

func (s *Bolt) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	encoded, err := encode(value, ttl)
	if err != nil {
		return err
	}
	return s.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(boltBucket).Put([]byte(key), encoded)
	})
}

func (s *Bolt) Delete(_ context.Context, key string) error {
	return s.db.Batch(func(tx *bolt.Tx) error {
		return tx.Bucket(boltBucket).Delete([]byte(key))
	})
}

func (s *Bolt) Incr(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	return s.IncrBy(ctx, key, 1, ttl)
}

func (s *Bolt) IncrBy(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	deadline, err := ttlDeadline(ttl)
	if err != nil {
		return 0, err
	}
	n, _, err := s.IncrByDeadline(ctx, key, delta, deadline)
	return n, err
}

func (s *Bolt) IncrByDeadline(_ context.Context, key string, delta, deadline int64) (int64, bool, error) {
	var n int64
	var applied bool
	err := s.db.Batch(func(tx *bolt.Tx) error {
		n, applied = 0, false // reset: Batch may retry this fn
		b := tx.Bucket(boltBucket)
		k := []byte(key)
		now := time.Now()
		// (2) A flush delayed past its window's deadline is a no-op.
		if deadline != 0 && now.UnixNano() >= deadline {
			if cur, ok := decode(b.Get(k), now); ok {
				v, err := strconv.ParseInt(string(cur), 10, 64)
				if err != nil {
					return err
				}
				n = v
			}
			return nil
		}
		raw := b.Get(k)
		if cur, ok := decode(raw, now); ok {
			// (4) Existing live key: add delta, keep the original expiry.
			v, err := strconv.ParseInt(string(cur), 10, 64)
			if err != nil {
				return err
			}
			n = v + delta
			out := make([]byte, 8, 8+20)
			copy(out, raw[:8])
			applied = true
			return b.Put(k, strconv.AppendInt(out, n, 10))
		}
		// (3) Fresh key: create at delta expiring exactly at the deadline.
		n = delta
		applied = true
		return b.Put(k, encodeAbs(strconv.AppendInt(nil, delta, 10), deadline))
	})
	return n, applied, err
}

func (s *Bolt) CompareAndSwap(_ context.Context, key string, old, new []byte, ttl time.Duration) (bool, error) {
	encoded, err := encode(new, ttl)
	if err != nil {
		return false, err
	}
	var swapped bool
	err = s.db.Batch(func(tx *bolt.Tx) error {
		swapped = false // reset: Batch may retry this fn
		b := tx.Bucket(boltBucket)
		k := []byte(key)
		cur, ok := decode(b.Get(k), time.Now())
		if old == nil {
			if ok {
				return nil
			}
		} else if !ok || !bytes.Equal(cur, old) {
			return nil
		}
		swapped = true
		return b.Put(k, encoded)
	})
	return swapped, err
}

func (s *Bolt) Scan(_ context.Context, prefix string) ([]KV, error) {
	var out []KV
	err := s.db.View(func(tx *bolt.Tx) error {
		now := time.Now()
		p := []byte(prefix)
		c := tx.Bucket(boltBucket).Cursor()
		for k, raw := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, raw = c.Next() {
			v, ok := decode(raw, now)
			if !ok {
				continue // expired but not yet swept
			}
			var exp time.Time
			if nano := binary.BigEndian.Uint64(raw); nano != 0 {
				exp = time.Unix(0, int64(nano))
			}
			out = append(out, KV{Key: string(k), Value: bytes.Clone(v), ExpiresAt: exp})
		}
		return nil
	})
	return out, err // cursor iteration is already key-ordered
}

func (s *Bolt) Close() error {
	close(s.done)
	return s.db.Close()
}
