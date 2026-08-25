// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"html/template"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/melroy89/angie-guardian/core/pow"
	"github.com/melroy89/angie-guardian/web"
)

func TestChallengeRendererMatchesTemplate(t *testing.T) {
	tmpl := template.Must(template.ParseFS(web.FS, "challenge.html.tmpl"))
	renderer := newChallengeRenderer()
	ids := []string{
		"0123456789abcdef0123456789abcdef",
		"s1." + strings.Repeat("Ab0_-", 180) + ".Ab0_-",
	}
	for _, id := range ids {
		for _, noScript := range []bool{false, true} {
			name := "js"
			if noScript {
				name = "nojs"
			}
			t.Run(name+"/id-length="+strconv.Itoa(len(id)), func(t *testing.T) {
				payload, err := json.Marshal(&challengePayload{
					ChallengeID: id,
					Challenge:   strings.Repeat("a", 64),
					Difficulty:  32,
					PassURL:     PassPath,
				}, jsontext.EscapeForHTML(true))
				if err != nil {
					t.Fatal(err)
				}
				refresh := 6
				data := &challengeData{
					JSON:           template.JS(payload),
					NoScript:       noScript,
					RefreshSeconds: refresh,
					NoJSURL:        PassPath + "?cid=" + id + "&nojs=1",
				}
				var want bytes.Buffer
				if err := tmpl.Execute(&want, data); err != nil {
					t.Fatal(err)
				}
				var got bytes.Buffer
				if err := renderer.Render(&got, payload, noScript, "6", id); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want.Bytes()) {
					t.Fatalf("compiled renderer differs from template\nwant %q\n got %q", want.Bytes(), got.Bytes())
				}
				got.Reset()
				if err := renderer.RenderChallenge(&got, &challengePayload{
					ChallengeID: id,
					Challenge:   strings.Repeat("a", 64),
					Difficulty:  32,
					PassURL:     PassPath,
				}, noScript, "6"); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want.Bytes()) {
					t.Fatalf("streaming renderer differs from template\nwant %q\n got %q", want.Bytes(), got.Bytes())
				}
			})
		}
	}
}

func TestChallengeRendererStreamingJSONMatchesMarshal(t *testing.T) {
	renderer := newChallengeRenderer()
	data := &challengePayload{
		ChallengeID: "id\"<>&\u2028\u2029",
		Challenge:   "challenge\n\t\x00\"<>&\u2028\u2029",
		Difficulty:  16,
		PassURL:     "/pass?next=\"<>&",
	}
	payload, err := json.Marshal(data, jsontext.EscapeForHTML(true))
	if err != nil {
		t.Fatal(err)
	}
	for _, noScript := range []bool{false, true} {
		var want bytes.Buffer
		if err := renderer.Render(&want, payload, noScript, "6", data.ChallengeID); err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		if err := renderer.RenderChallenge(&got, data, noScript, "6"); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("noScript=%t: streamed output differs from Marshal renderer\nwant %q\n got %q", noScript, want.Bytes(), got.Bytes())
		}
		embedded := dataRe.FindSubmatch(got.Bytes())
		if embedded == nil {
			t.Fatalf("noScript=%t: embedded JSON missing", noScript)
		}
		if bytes.Contains(embedded[1], []byte(`<`)) || bytes.Contains(embedded[1], []byte(`>`)) || bytes.Contains(embedded[1], []byte(`&`)) {
			t.Fatalf("noScript=%t: HTML-special JSON was emitted raw: %q", noScript, embedded[1])
		}
		if !bytes.Contains(embedded[1], []byte(`\u003c`)) || !bytes.Contains(embedded[1], []byte(`\u0026`)) {
			t.Fatalf("noScript=%t: HTML-safe escapes missing: %q", noScript, embedded[1])
		}
	}
}

func TestChallengePageContainsBoundedArgonRetryAndFallbackLogic(t *testing.T) {
	renderer := newChallengeRenderer()
	data := &challengePayload{
		ChallengeID: "id", Challenge: "challenge", Algorithm: pow.AlgorithmArgon2ID,
		MemoryKiB: 8192, Iterations: 1, Salt: strings.Repeat("a", 32),
		PassURL: PassPath, WorkerURL: argonWorkerURL, WASMURL: argonWASMURL,
		NoScriptFallback: true, NoScriptURL: PassPath + "?cid=id&nojs=1", NoScriptWaitSeconds: 5,
	}
	var page bytes.Buffer
	if err := renderer.RenderChallenge(&page, data, true, "6"); err != nil {
		t.Fatal(err)
	}
	for _, contract := range []string{
		`resp.status !== 429 && resp.status !== 503`, `Math.random() * 1500`, `body[solution.kind]`,
		`new Worker(data.worker_url)`, `data.noscript_wait_seconds * 1000`,
	} {
		if !strings.Contains(page.String(), contract) {
			t.Errorf("challenge page missing %q", contract)
		}
	}
}

func TestChallengeRendererConcurrent(t *testing.T) {
	renderer := newChallengeRenderer()
	data := &challengePayload{ChallengeID: "id", Challenge: "challenge", Difficulty: 16, PassURL: PassPath}
	var want bytes.Buffer
	if err := renderer.RenderChallenge(&want, data, true, "6"); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				var got bytes.Buffer
				if err := renderer.RenderChallenge(&got, data, true, "6"); err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got.Bytes(), want.Bytes()) {
					errs <- errors.New("concurrent render differed")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestChallengeRendererPropagatesWriteFailures(t *testing.T) {
	renderer := newChallengeRenderer()
	want := errors.New("connection closed")
	if err := renderer.Render(errorWriter{err: want}, []byte(`{}`), false, "", "id"); !errors.Is(err, want) {
		t.Fatalf("write error = %v, want %v", err, want)
	}
	if err := renderer.Render(shortWriter{}, []byte(`{}`), false, "", "id"); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error = %v, want %v", err, io.ErrShortWrite)
	}
	data := &challengePayload{ChallengeID: "id", Challenge: "challenge", Difficulty: 16, PassURL: PassPath}
	if err := renderer.RenderChallenge(errorWriter{err: want}, data, false, ""); !errors.Is(err, want) {
		t.Fatalf("streaming write error = %v, want %v", err, want)
	}
	jsonFailure := &failOnWrite{at: 2, err: want}
	if err := renderer.RenderChallenge(jsonFailure, data, false, ""); !errors.Is(err, want) {
		t.Fatalf("streaming JSON write error = %v, want %v", err, want)
	}
	// A failed stream must not affect the next request.
	var got bytes.Buffer
	if err := renderer.RenderChallenge(&got, data, false, ""); err != nil {
		t.Fatalf("render after streaming failure: %v", err)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type failOnWrite struct {
	writes int
	at     int
	err    error
}

func (w *failOnWrite) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.at {
		return 0, w.err
	}
	return len(p), nil
}
