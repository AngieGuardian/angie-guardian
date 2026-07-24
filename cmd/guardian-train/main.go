// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// guardian-train builds and validates Guardian anomaly-model artifacts.
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/melroy89/angie-guardian/core/anomaly"
)

var version = "dev" // set via -ldflags "-X main.version=..."

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

type inputStats struct {
	Lines          int64 `json:"lines"`
	Included       int64 `json:"included"`
	FilteredStatus int64 `json:"filtered_status"`
	FilteredAction int64 `json:"filtered_action"`
	MalformedJSON  int64 `json:"malformed_json"`
	InvalidSchema  int64 `json:"invalid_schema"`
}

func (s inputStats) invalid() int64 { return s.MalformedJSON + s.InvalidSchema }

type trainDomainReport struct {
	Requests int64 `json:"requests"`
	Segments int   `json:"segments"`
}

type trainReport struct {
	GeneratedAt string                       `json:"generated_at"`
	Input       inputStats                   `json:"input"`
	Domains     map[string]trainDomainReport `json:"domains"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-version" || args[0] == "--version") {
		fmt.Fprintln(stdout, "guardian-train", version)
		return 0
	}
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "train":
		return runTrain(args[1:], stdout, stderr)
	case "compare":
		return runCompare(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage:")
	fmt.Fprintln(w, "  guardian-train train [options] access.json [access.json.gz ...]")
	fmt.Fprintln(w, "  guardian-train compare [options] access.json [access.json.gz ...]")
	fmt.Fprintln(w, "  guardian-train -version")
}

func runTrain(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("train", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "model.json", "candidate model output path")
	reportPath := fs.String("report", "", "write machine-readable training report")
	minRequests := fs.Int64("min-requests", 5000, "minimum usable records per domain")
	minSegmentRequests := fs.Int64("min-segment-requests", 500, "minimum records per segment")
	maxSegments := fs.Int("max-segments", 128, "maximum retained segments per domain")
	maxInvalid := fs.Int64("max-invalid", 0, "maximum malformed or invalid records")
	var required stringList
	fs.Var(&required, "require-domain", "normalized domain required in the artifact (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 || *minRequests <= 0 || *minSegmentRequests <= 0 || *maxSegments <= 0 || *maxSegments > 4096 || *maxInvalid < 0 {
		fmt.Fprintln(stderr, "train requires inputs, positive request limits, 1..4096 segments, and a non-negative invalid limit")
		return 2
	}
	paths, cleanup, err := materializeStdin(fs.Args())
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	defer cleanup()

	selector := anomaly.NewSegmentSelector(*maxSegments)
	stats := inputStats{}
	if err := scanEligibleInputs(paths, &stats, stderr, selector.Observe); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if stats.invalid() > *maxInvalid {
		fmt.Fprintf(stderr, "refusing candidate: %d malformed/invalid records exceeds maximum %d\n", stats.invalid(), *maxInvalid)
		return 1
	}

	trainer := anomaly.NewTrainer(selector.Selected(*maxSegments), *minSegmentRequests)
	// Re-validate the exact aggregation pass independently. Active access logs
	// can grow between the discovery and aggregation passes; silently ignoring
	// a newly appended malformed record would let the final artifact bypass the
	// configured input-hygiene limit and make its report describe another pass.
	stats = inputStats{}
	if err := scanEligibleInputs(paths, &stats, stderr, trainer.Add); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if stats.invalid() > *maxInvalid {
		fmt.Fprintf(stderr, "refusing candidate: %d malformed/invalid records exceeds maximum %d during aggregation\n", stats.invalid(), *maxInvalid)
		return 1
	}
	model := trainer.Finish(*minRequests)
	for _, host := range required {
		if !model.HasDomain(host) {
			fmt.Fprintf(stderr, "refusing candidate: required domain %q has no baseline\n", host)
			return 1
		}
	}
	if len(model.Domains) == 0 {
		fmt.Fprintf(stderr, "no domain reached %d usable records; model not written\n", *minRequests)
		return 1
	}
	if err := model.Save(*out); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}

	report := trainReport{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Input: stats, Domains: make(map[string]trainDomainReport)}
	hosts := make([]string, 0, len(model.Domains))
	for host, d := range model.Domains {
		hosts = append(hosts, host)
		report.Domains[host] = trainDomainReport{Requests: d.Baseline.Requests, Segments: len(d.Segments)}
	}
	sort.Strings(hosts)
	if *reportPath != "" {
		if err := writeJSON(*reportPath, report); err != nil {
			fmt.Fprintln(stderr, "error writing report:", err)
			return 1
		}
	}
	fmt.Fprintf(stdout, "model written to %s (%d included, %d status-filtered, %d action-filtered, %d malformed/invalid)\n",
		*out, stats.Included, stats.FilteredStatus, stats.FilteredAction, stats.invalid())
	for _, host := range hosts {
		d := report.Domains[host]
		fmt.Fprintf(stdout, "  %-40s %8d requests, %3d segments\n", host, d.Requests, d.Segments)
	}
	return 0
}

func runCompare(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(stderr)
	currentPath := fs.String("current", "", "current live model")
	candidatePath := fs.String("candidate", "", "candidate model")
	reportPath := fs.String("report", "", "write machine-readable comparison report")
	minRequests := fs.Int64("min-requests", 500, "minimum comparison records per domain")
	maxMeanDelta := fs.Float64("max-mean-delta", .10, "maximum absolute mean-score drift")
	maxP95Delta := fs.Float64("max-p95-delta", .15, "maximum absolute p95-score drift")
	maxInvalid := fs.Int64("max-invalid", 0, "maximum malformed or invalid records")
	var required stringList
	fs.Var(&required, "require-domain", "scope hard coverage failures to this normalized domain (repeatable); without any, every coverage hole fails")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 || *currentPath == "" || *candidatePath == "" || *minRequests <= 0 ||
		*maxMeanDelta < 0 || *maxMeanDelta > 1 || *maxP95Delta < 0 || *maxP95Delta > 1 || *maxInvalid < 0 {
		fmt.Fprintln(stderr, "compare requires models, inputs, and valid limits")
		return 2
	}
	current, err := anomaly.Load(*currentPath)
	if err != nil {
		fmt.Fprintln(stderr, "error loading current model:", err)
		return 1
	}
	candidate, err := anomaly.Load(*candidatePath)
	if err != nil {
		fmt.Fprintln(stderr, "error loading candidate model:", err)
		return 1
	}
	comparator := anomaly.NewComparator(current, candidate)
	comparator.SetRequired(required)
	stats := inputStats{}
	if err := scanInputs(fs.Args(), func(source string, lineNo int64, line []byte) error {
		rec, err := parseRecord(source, lineNo, line, &stats, stderr)
		if err != nil {
			return nil
		}
		switch anomaly.Eligible(&rec) {
		case anomaly.FilterStatus:
			stats.FilteredStatus++
		case anomaly.FilterAction:
			stats.FilteredAction++
		default:
			stats.Included++
			comparator.Add(&rec)
		}
		return nil
	}); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	if stats.invalid() > *maxInvalid {
		fmt.Fprintf(stderr, "comparison invalid: %d malformed/invalid records exceeds maximum %d\n", stats.invalid(), *maxInvalid)
		return 1
	}
	report := comparator.Report(*minRequests, *maxMeanDelta, *maxP95Delta, time.Now().UTC().Format(time.RFC3339Nano))
	if *reportPath != "" {
		if err := writeJSON(*reportPath, report); err != nil {
			fmt.Fprintln(stderr, "error writing report:", err)
			return 1
		}
	}
	hosts := make([]string, 0, len(report.Domains))
	for host := range report.Domains {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		d := report.Domains[host]
		fmt.Fprintf(stdout, "%-40s %-9s mean %.3f -> %.3f (%+.3f), p95 %.2f -> %.2f (%+.2f), pass=%t\n",
			host, d.Status, d.Current.Mean, d.Candidate.Mean, d.MeanDelta, d.Current.P95, d.Candidate.P95, d.P95Delta, d.Passed)
		for _, failure := range d.Failures {
			fmt.Fprintf(stdout, "  reject: %s\n", failure)
		}
	}
	if !report.Passed {
		fmt.Fprintln(stderr, "candidate comparison rejected")
		return 3
	}
	fmt.Fprintln(stdout, "candidate comparison passed")
	return 0
}

func parseRecord(source string, lineNo int64, line []byte, stats *inputStats, stderr io.Writer) (anomaly.LogRecord, error) {
	stats.Lines++
	rec, err := anomaly.ParseLogRecord(line)
	if err == nil {
		return rec, nil
	}
	if json.Valid(line) {
		stats.InvalidSchema++
	} else {
		stats.MalformedJSON++
	}
	if stats.invalid() <= 10 {
		fmt.Fprintf(stderr, "%s:%d: invalid record: %v\n", source, lineNo, err)
	}
	return rec, err
}

func scanEligibleInputs(paths []string, stats *inputStats, stderr io.Writer, observe func(*anomaly.LogRecord)) error {
	return scanInputs(paths, func(source string, lineNo int64, line []byte) error {
		rec, err := parseRecord(source, lineNo, line, stats, stderr)
		if err != nil {
			return nil
		}
		switch anomaly.Eligible(&rec) {
		case anomaly.FilterStatus:
			stats.FilteredStatus++
		case anomaly.FilterAction:
			stats.FilteredAction++
		default:
			stats.Included++
			observe(&rec)
		}
		return nil
	})
}

func scanInputs(paths []string, fn func(source string, lineNo int64, line []byte) error) error {
	for _, path := range paths {
		if err := scanInput(path, fn); err != nil {
			return err
		}
	}
	return nil
}

func scanInput(path string, fn func(source string, lineNo int64, line []byte) error) error {
	var r io.Reader
	var closeFns []func() error
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		r = f
		closeFns = append(closeFns, f.Close)
		if strings.HasSuffix(strings.ToLower(path), ".gz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				_ = f.Close()
				return fmt.Errorf("open gzip %s: %w", path, err)
			}
			r = gz
			closeFns = append([]func() error{gz.Close}, closeFns...)
		}
	}
	sc := bufio.NewScanner(r)
	// Scanner's maximum includes the delimiter/read-ahead byte. Leave one byte
	// beyond the parser's record limit so an exactly-MaxLogLineBytes line reaches
	// ParseLogRecord, while a larger line still fails the scan.
	sc.Buffer(make([]byte, 64*1024), anomaly.MaxLogLineBytes+1)
	var lineNo int64
	var callbackErr error
	for sc.Scan() {
		lineNo++
		if err := fn(path, lineNo, sc.Bytes()); err != nil {
			callbackErr = err
			break
		}
	}
	scanErr := sc.Err()
	var closeErr error
	for _, closeFn := range closeFns {
		closeErr = errors.Join(closeErr, closeFn())
	}
	if scanErr != nil {
		return fmt.Errorf("reading %s: %w", path, scanErr)
	}
	if callbackErr != nil {
		return errors.Join(callbackErr, closeErr)
	}
	return closeErr
}

func materializeStdin(paths []string) ([]string, func(), error) {
	count := 0
	for _, path := range paths {
		if path == "-" {
			count++
		}
	}
	if count == 0 {
		return paths, func() {}, nil
	}
	if count > 1 {
		return nil, func() {}, fmt.Errorf("stdin may be listed only once")
	}
	f, err := os.CreateTemp("", "guardian-train-stdin-*.json")
	if err != nil {
		return nil, func() {}, err
	}
	name := f.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := io.Copy(f, os.Stdin); err != nil {
		_ = f.Close()
		cleanup()
		return nil, func() {}, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	out := append([]string(nil), paths...)
	for i := range out {
		if out[i] == "-" {
			out[i] = name
		}
	}
	return out, cleanup, nil
}

func writeJSON(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
