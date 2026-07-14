// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// guardian-train builds the anomaly-detection baseline from Angie JSON
// access logs (the guardian_json format from deploy/angie-json-log.conf)
// and writes the model artifact guardiand scores against. Run it from cron;
// guardiand hot-swaps the artifact when the file changes.
//
//	guardian-train -out /etc/guardian/model.json /var/log/angie/*.access.json
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/melroy89/angie-guardian/core/anomaly"
)

var version = "dev" // set via -ldflags "-X main.version=..."

func main() {
	out := flag.String("out", "model.json", "output model artifact path")
	minRequests := flag.Int64("min-requests", 1000, "drop domains with fewer usable successful records (a thin baseline misclassifies)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("guardian-train", version)
		return
	}
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: guardian-train -out model.json access1.json [access2.json ...]")
		fmt.Fprintln(os.Stderr, "       use - to read from stdin")
		os.Exit(2)
	}

	trainer := &anomaly.Trainer{}
	var lines, badLines int64
	for _, path := range flag.Args() {
		if err := addTrainingInput(path, trainer, &lines, &badLines); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}

	model := trainer.Finish(*minRequests)
	if len(model.Domains) == 0 {
		fmt.Fprintf(os.Stderr, "no domain reached %d requests — model not written (got %d lines, %d unparseable)\n",
			*minRequests, lines, badLines)
		os.Exit(1)
	}
	if err := model.Save(*out); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	fmt.Printf("model written to %s (%d lines read, %d unparseable)\n", *out, lines, badLines)
	hosts := make([]string, 0, len(model.Domains))
	for h := range model.Domains {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		b := model.Domains[h]
		fmt.Printf("  %-40s %8d requests, %3d UA prefixes, %3d path prefixes\n",
			h, b.Requests, len(b.UAFreq), len(b.PathPrefixFreq))
	}
}

func addTrainingInput(path string, trainer *anomaly.Trainer, lines, badLines *int64) error {
	if path == "-" {
		return scanTrainingInput(path, os.Stdin, trainer, lines, badLines)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	scanErr := scanTrainingInput(path, f, trainer, lines, badLines)
	closeErr := f.Close()
	if scanErr != nil {
		return scanErr
	}
	return closeErr
}

func scanTrainingInput(path string, r io.Reader, trainer *anomaly.Trainer, lines, badLines *int64) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		*lines++
		var rec anomaly.LogRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			*badLines++
			continue
		}
		trainer.Add(&rec)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return nil
}
