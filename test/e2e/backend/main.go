// Test backend for the Angie end-to-end harness.
//
// The public listener behaves like the whoami service used previously, while
// the private management listener exposes an exact request count. Tests use
// that count to assert that rejected or shed traffic never reached the origin.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
)

var requests atomic.Int64

func main() {
	public := http.NewServeMux()
	public.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"hostname":              "e2e-backend",
			"path":                  r.URL.Path,
			"headers":               r.Header,
			"backend_request_count": n,
		})
	})
	public.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Hostname: e2e-backend\nPath: %s\nBackend-Request-Count: %d\n", r.URL.Path, n)
		if len(body) > 0 {
			_, _ = w.Write(body)
		}
	})

	management := http.NewServeMux()
	management.HandleFunc("/count", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%d\n", requests.Load())
	})

	go func() {
		if err := http.ListenAndServe(":8081", management); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
	if err := http.ListenAndServe(":8080", public); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
