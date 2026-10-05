// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWaitListeningHealthResponse(t *testing.T) {
	for _, mode := range []string{"normal", "large", "stalled", "non200"} {
		t.Run(mode, func(t *testing.T) {
			release := make(chan struct{})
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/healthz" {
					t.Errorf("probe path = %q, want /healthz", r.URL.Path)
				}
				if mode == "non200" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				switch mode {
				case "normal":
					_, _ = w.Write([]byte("ok\n"))
				case "large":
					_, _ = w.Write([]byte(strings.Repeat("x", 1<<20)))
				case "stalled":
					// The headers establish readiness. Leave the body unfinished
					// to prove the probe does not wait for the complete payload.
					w.Header().Set("Content-Length", "1048576")
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}
			}))
			server.Start() // readiness probes deliberately exercise a real TCP listener
			t.Cleanup(func() { close(release) })
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			timeout := 2 * time.Second
			if mode == "non200" {
				timeout = 100 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() { done <- waitListening(ctx, server.Listener.Addr().String(), "", "", timeout) }()
			select {
			case err := <-done:
				if mode == "non200" {
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("non-200 probe = %v, want deadline exceeded", err)
					}
				} else if err != nil {
					t.Fatalf("health probe failed: %v", err)
				}
			case <-time.After(time.Second):
				cancel()
				<-done
				t.Fatal("probe waited for the response body after receiving healthy headers")
			}
		})
	}
}
