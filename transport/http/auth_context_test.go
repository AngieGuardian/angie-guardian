// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestAuthContextResetClearsRequest(t *testing.T) {
	s := &Server{}
	c := newAuthContext()
	r := authRequest("/private/../first?token=synthetic", "FIRST.test", "198.51.100.7", "FIRST-UA", "first-cookie")
	r.Header.Set("Referer", "first-referer")
	c.headers = r.Header
	s.fillRequestContext(r, &c.request, c.values)
	c.request.NormalizedPath()
	c.request.LowerUA()
	resetAuthContext(c)
	if len(c.values("Referer")) != 0 || c.values("host")[0] != "" || c.request.Cookie != "" || c.request.LowerUA() != "" {
		t.Fatal("released context exposes previous request data")
	}
}

func TestAuthContextParallelIsolation(t *testing.T) {
	s := &Server{}
	var wg sync.WaitGroup
	for worker := range 32 {
		wg.Go(func() {
			for iteration := range 100 {
				id := fmt.Sprintf("%d-%d", worker, iteration)
				host, ua := id+".test", "UA-"+id
				r := authRequest("/"+id, host, "198.51.100.7", ua, id)
				r.Header.Set("Referer", id)
				c := authContexts.Get().(*authContext)
				c.headers = r.Header
				s.fillRequestContext(r, &c.request, c.values)
				q := &c.request
				if q.Host != host || q.Cookie != id || q.NormalizedPath() != "/"+id || q.LowerUA() != strings.ToLower(ua) || q.HeaderValues("host")[0] != host || q.HeaderValues("referer")[0] != id {
					t.Errorf("request inherited another context: %+v", q)
				}
				releaseAuthContext(c)
			}
		})
	}
	wg.Wait()
}

func TestRequestContextKeepsDirectFallbacks(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "http://fallback.test/a?b=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = "[2001:db8::1]:1234"
	r.Header.Set("User-Agent", "fallback")
	q := (&Server{}).requestContext(r)
	if q.Host != "fallback.test" || q.Method != http.MethodPost || q.URI != "/a?b=1" || q.RemoteAddr != "2001:db8::1" || q.HeaderValues("HOST")[0] != q.Host {
		t.Fatalf("direct fallback changed: %+v", q)
	}
}
