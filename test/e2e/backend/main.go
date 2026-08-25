// Test backend for the Angie end-to-end harness.
//
// The public listener behaves like the whoami service used previously, while
// the private management listener exposes an exact request count. Tests use
// that count to assert that rejected or shed traffic never reached the origin.
package main

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

var requests atomic.Int64

const largeResponseSize = 64 << 20

func main() {
	public := http.NewServeMux()
	public.HandleFunc("/held-response", func(w http.ResponseWriter, _ *http.Request) {
		n := requests.Add(1)
		time.Sleep(8 * time.Second)
		fmt.Fprintf(w, "Backend-Request-Count: %d\n", n)
	})
	public.HandleFunc("/large-response", func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(largeResponseSize))
		chunk := make([]byte, 32<<10)
		for written := 0; written < largeResponseSize; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	public.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.MarshalWrite(w, map[string]any{
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
