// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"

	"github.com/melroy89/angie-guardian/core/store"
)

// profiler writes bounded, opt-in evidence for a single daemon run. Its
// ticker and runtime profiling are never started unless -profile-dir is set.
type profiler struct {
	dir       string
	cpu       *os.File
	samples   *os.File
	sampleOut io.Writer
	flight    *trace.FlightRecorder
	done      chan struct{}
	wg        sync.WaitGroup
	mu        sync.RWMutex
	pebble    *store.Pebble
	errMu     sync.Mutex
	writeErr  error
}

type profileSample struct {
	At         time.Time          `json:"at"`
	HeapLive   uint64             `json:"heap_live_bytes"`
	HeapSys    uint64             `json:"heap_sys_bytes"`
	HeapObjs   uint64             `json:"heap_objects"`
	GCs        uint32             `json:"gc_cycles"`
	Goroutines int                `json:"goroutines"`
	Pebble     *store.PebbleStats `json:"pebble,omitempty"`
}

func startProfiler(dir string) (*profiler, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if !os.IsExist(err) {
			return nil, fmt.Errorf("create profile directory: %w", err)
		}
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			return nil, fmt.Errorf("read profile directory: %w", readErr)
		}
		if len(entries) != 0 {
			return nil, fmt.Errorf("profile directory %s must be empty", dir)
		}
	}
	cpu, err := os.Create(filepath.Join(dir, "cpu.pprof"))
	if err != nil {
		return nil, fmt.Errorf("create CPU profile: %w", err)
	}
	samples, err := os.Create(filepath.Join(dir, "samples.jsonl"))
	if err != nil {
		_ = cpu.Close()
		return nil, fmt.Errorf("create profile samples: %w", err)
	}
	if err := pprof.StartCPUProfile(cpu); err != nil {
		_ = samples.Close()
		_ = cpu.Close()
		return nil, fmt.Errorf("start CPU profile: %w", err)
	}
	flight := trace.NewFlightRecorder(trace.FlightRecorderConfig{MinAge: 10 * time.Second, MaxBytes: 8 << 20})
	if err := flight.Start(); err != nil {
		pprof.StopCPUProfile()
		_ = samples.Close()
		_ = cpu.Close()
		return nil, fmt.Errorf("start runtime flight recorder: %w", err)
	}
	p := &profiler{dir: dir, cpu: cpu, samples: samples, sampleOut: samples, flight: flight, done: make(chan struct{})}
	p.wg.Add(1)
	go p.sampleLoop()
	return p, nil
}

func (p *profiler) attachPebble(db *store.Pebble) {
	p.mu.Lock()
	p.pebble = db
	p.mu.Unlock()
}

func (p *profiler) sampleLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		p.writeSample()
		select {
		case <-p.done:
			return
		case <-ticker.C:
		}
	}
}

func (p *profiler) writeSample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := profileSample{At: time.Now().UTC(), HeapLive: ms.HeapAlloc, HeapSys: ms.HeapSys, HeapObjs: ms.HeapObjects, GCs: ms.NumGC, Goroutines: runtime.NumGoroutine()}
	p.mu.RLock()
	db := p.pebble
	p.mu.RUnlock()
	if db != nil {
		stats := db.Stats()
		s.Pebble = &stats
	}
	if err := json.MarshalWrite(p.sampleOut, &s); err != nil {
		p.recordWriteErr(fmt.Errorf("write JSONL sample: %w", err))
		return
	}
	if _, err := io.WriteString(p.sampleOut, "\n"); err != nil {
		p.recordWriteErr(fmt.Errorf("write JSONL delimiter: %w", err))
	}
}

func (p *profiler) recordWriteErr(err error) {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	if p.writeErr == nil {
		p.writeErr = err
	}
}

func (p *profiler) sampleWriteErr() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.writeErr
}

func (p *profiler) stop() error {
	if p == nil {
		return nil
	}
	close(p.done)
	p.wg.Wait()
	pprof.StopCPUProfile()
	first := p.sampleWriteErr()
	if p.flight != nil {
		f, err := os.Create(filepath.Join(p.dir, "flight.trace"))
		if err == nil {
			_, err = p.flight.WriteTo(f)
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
		}
		p.flight.Stop()
		if first == nil && err != nil {
			first = err
		}
	}
	for _, name := range []string{"heap", "allocs", "mutex", "block", "goroutineleak"} {
		f, err := os.Create(filepath.Join(p.dir, name+".pprof"))
		if err == nil {
			err = pprof.Lookup(name).WriteTo(f, 0)
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
		}
		if first == nil && err != nil {
			first = err
		}
	}
	if err := p.cpu.Close(); first == nil {
		first = err
	}
	if err := p.samples.Close(); first == nil {
		first = err
	}
	return first
}
