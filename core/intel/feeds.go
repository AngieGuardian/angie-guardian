// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package intel

import (
	"context"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Feed actions. A deny feed rejects matching IPs outright; a challenge feed
// makes them prove work first (only meaningful on PoW-enabled domains).
const (
	FeedActionDeny      = "deny"
	FeedActionChallenge = "challenge"
)

// FeedConfig describes one reputation feed: a plain-text list of IPs/CIDRs,
// pulled from a URL on a refresh interval or read from a local file (which is
// hot-reloaded like the WAF rules files). Exactly one of URL/File is set.
type FeedConfig struct {
	Name    string
	URL     string
	File    string
	Refresh time.Duration
	Action  string // FeedActionDeny or FeedActionChallenge
}

// maxFeedBody caps a fetched feed. The biggest common feeds (full FireHOL
// level sets) are a few MB; anything past this is a misconfigured URL (an
// HTML page, a tarball) and must not OOM the daemon.
const maxFeedBody = 64 << 20

// feedRetryInterval is how long after a failed fetch the next attempt runs,
// capped by the feed's own refresh interval.
const feedRetryInterval = 5 * time.Minute

// feed is one live feed: config plus the atomically swapped parsed state.
type feed struct {
	cfg     FeedConfig
	state   atomic.Pointer[feedState]
	lastErr atomic.Pointer[string]

	// Content hash of the last load, poll-goroutine-only (file feeds).
	hash uint64
}

// feedState is the immutable result of one successful load.
type feedState struct {
	set       *rangeSet
	entries   int
	refreshed time.Time
	source    string // "url", "file" or "cache"
}

// FeedStatus is the admin-API view of one feed.
type FeedStatus struct {
	Name        string     `json:"name"`
	Action      string     `json:"action"`
	Source      string     `json:"source"` // configured origin: the URL or file path
	Loaded      bool       `json:"loaded"`
	LoadedFrom  string     `json:"loaded_from,omitempty"` // url | file | cache
	Entries     int        `json:"entries"`
	LastRefresh *time.Time `json:"last_refresh,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

func (f *feed) status() FeedStatus {
	origin := f.cfg.URL
	if origin == "" {
		origin = f.cfg.File
	}
	s := FeedStatus{Name: f.cfg.Name, Action: f.cfg.Action, Source: origin}
	if st := f.state.Load(); st != nil {
		s.Loaded, s.LoadedFrom, s.Entries = true, st.source, st.entries
		t := st.refreshed
		s.LastRefresh = &t
	}
	if e := f.lastErr.Load(); e != nil {
		s.LastError = *e
	}
	return s
}

// install parses raw and swaps it in as the feed's current state. A body with
// lines but not a single valid entry is rejected: that is an error page or a
// format we don't speak, and keeping the previous state beats matching nothing.
func (f *feed) install(raw []byte, source string, now time.Time) (int, error) {
	prefixes, invalid := ParseList(raw)
	if len(prefixes) == 0 && invalid > 0 {
		return 0, fmt.Errorf("no valid entries (%d invalid lines): not an IP list?", invalid)
	}
	f.state.Store(&feedState{
		set:       newRangeSet(prefixes),
		entries:   len(prefixes),
		refreshed: now,
		source:    source,
	})
	f.hash = contentHash(raw)
	return invalid, nil
}

func (f *feed) contains(addr netip.Addr) bool {
	st := f.state.Load()
	return st != nil && st.set.Contains(addr)
}

// contentHash fingerprints feed bytes so file polling reloads on content
// change, independent of mtime resolution (same approach as the rules cache).
func contentHash(raw []byte) uint64 {
	h := fnv.New64a()
	h.Write(raw)
	return h.Sum64()
}

// cachePath is where a URL feed's last good body is persisted, so a restart
// serves yesterday's list instead of nothing while the first fetch runs.
func (f *feed) cachePath(cacheDir string) string {
	if cacheDir == "" || f.cfg.URL == "" {
		return ""
	}
	return filepath.Join(cacheDir, f.cfg.Name+".list")
}

// fetch pulls the feed URL, installs the body and persists it to the cache.
// ctx aborts the request mid-flight, so a stalled remote cannot hold up
// provider shutdown.
func (f *feed) fetch(ctx context.Context, client *http.Client, cacheDir string, log *slog.Logger) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "angie-guardian feed fetcher (+https://github.com/melroy89/angie-guardian)")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBody+1))
	if err != nil {
		return err
	}
	if len(raw) > maxFeedBody {
		return fmt.Errorf("body exceeds %d bytes", maxFeedBody)
	}
	invalid, err := f.install(raw, "url", time.Now())
	if err != nil {
		return err
	}
	if invalid > 0 {
		log.Warn("feed has invalid lines", "feed", f.cfg.Name, "invalid", invalid)
	}
	if path := f.cachePath(cacheDir); path != "" {
		if err := writeFileAtomic(path, raw); err != nil {
			log.Warn("feed cache write failed", "feed", f.cfg.Name, "path", path, "err", err)
		}
	}
	return nil
}

// loadCache seeds a URL feed from its persisted copy at startup. Returns the
// cache file's mtime (zero when there is no usable cache).
func (f *feed) loadCache(cacheDir string) time.Time {
	path := f.cachePath(cacheDir)
	if path == "" {
		return time.Time{}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	if _, err := f.install(raw, "cache", st.ModTime()); err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

// loadFile (re)loads a local file feed when its content changed. The initial
// load (force=true) propagates errors so a missing file fails startup, like
// the WAF rules files do.
func (f *feed) loadFile(force bool, log *slog.Logger) error {
	raw, err := os.ReadFile(f.cfg.File)
	if err != nil {
		if !force {
			log.Warn("feed file unreadable, keeping loaded entries", "feed", f.cfg.Name, "err", err)
			return nil
		}
		return err
	}
	if !force && contentHash(raw) == f.hash {
		return nil
	}
	invalid, err := f.install(raw, "file", time.Now())
	if err != nil {
		if !force {
			// Remember the broken content so the same version is not retried
			// (and logged) every poll.
			f.hash = contentHash(raw)
			log.Error("feed file reload failed, keeping previous entries", "feed", f.cfg.Name, "err", err)
			return nil
		}
		return fmt.Errorf("feed %s: %s: %w", f.cfg.Name, f.cfg.File, err)
	}
	if invalid > 0 {
		log.Warn("feed has invalid lines", "feed", f.cfg.Name, "invalid", invalid)
	}
	if !force {
		log.Info("feed file reloaded", "feed", f.cfg.Name, "entries", f.state.Load().entries)
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".feed-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
