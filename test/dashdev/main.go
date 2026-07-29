// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command dashdev serves the reporting dashboard from the working tree while
// forwarding every other admin path to a guardiand that is already running
// somewhere else, so a dashboard change can be tried against real data without
// building or deploying a binary:
//
//	make dashboard-dev                                        # a local seed instance
//	make dashboard-dev UPSTREAM=http://192.168.1.42:8072      # a real deployment
//
// It works because the dashboard's URLs are origin-relative: the page fetches
// "/admin/stats" and loads "chart.umd.min.js" relative to /admin/dashboard. Any
// listener answering both the page and /admin/* therefore serves it unmodified,
// with no CORS, no config key and no change to the page.
//
// Deliberately a separate dev command rather than a mode of guardiand. The
// alternatives all pay for this convenience in the production binary: opening
// the admin API to cross-origin browsers needs CORS on a token-guarded API,
// serving the page off disk adds a filesystem read path plus ambiguity about
// which HTML is live, and a forwarding mode inside guardiand puts an
// operator-authenticated reverse proxy into a security daemon. This costs the
// shipped binary nothing.
//
// The upstream is a real daemon, and the dashboard's write actions (unblock,
// clearing counters) are forwarded like everything else. Against production
// they act on production.
package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/melroy89/angie-guardian/web"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8073", "address to serve the dashboard on")
	upstream := flag.String("upstream", "http://127.0.0.1:18072",
		"guardiand admin listener to forward data requests to (default is the seed instance)")
	page := flag.String("page", "web/dashboard.html",
		"dashboard HTML to serve; empty serves the copy embedded in this build")
	flag.Parse()

	target, err := url.Parse(*upstream)
	if err != nil || target.Host == "" {
		log.Fatalf("-upstream must be an absolute URL like http://host:port, got %q", *upstream)
	}
	// NewSingleHostReverseProxy rewrites scheme and host and forwards headers
	// untouched, which is what makes the in-page token work: the daemon
	// authenticates the operator's bearer token exactly as it would its own
	// page. Same origin also means the browser sends no preflight.
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		log.Printf("upstream %s: %v", target, err)
		http.Error(w, "upstream unreachable: "+err.Error(), http.StatusBadGateway)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/admin/dashboard", func(w http.ResponseWriter, r *http.Request) {
		body, from, err := dashboardHTML(*page)
		if err != nil {
			log.Printf("%s: %v", from, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Read per request, so saving the file and reloading the tab is the
		// whole edit loop. No Content-Security-Policy on purpose: guardiand
		// sets a fitted one on its own dashboard route, and reproducing it here
		// would only let a local experiment fail for a reason that has nothing
		// to do with what is being tried.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
		log.Printf("%s %s -> %s (%d bytes)", r.Method, r.URL.Path, from, len(body))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Everything else is real data or a vendored library, and comes from the
		// daemon: the JSON endpoints, the write actions, Chart.js and its
		// modules, the TopoJSON atlas the map draws.
		if !strings.HasPrefix(r.URL.Path, "/admin/") {
			http.NotFound(w, r)
			return
		}
		log.Printf("%s %s -> %s", r.Method, r.URL.RequestURI(), target)
		proxy.ServeHTTP(w, r)
	})

	_, from, err := dashboardHTML(*page)
	if err != nil {
		log.Fatalf("%s: %v", from, err) // fail now, not on the first request
	}
	log.Printf("serving %s; every other /admin/ path is forwarded to %s", from, target)
	log.Printf("write actions on that page act on %s for real", target)
	log.Printf("open http://%s/admin/dashboard   (enter the upstream's admin token, or append #token=...)", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

// dashboardHTML returns the page to serve and a label for it. An empty path
// means the embedded copy, which makes the command useful as a plain viewer for
// a remote daemon as well as an edit loop.
func dashboardHTML(path string) ([]byte, string, error) {
	if path == "" {
		b, err := web.FS.ReadFile("dashboard.html")
		return b, "the embedded dashboard.html", err
	}
	b, err := os.ReadFile(path)
	return b, path, err
}
