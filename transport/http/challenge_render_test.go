// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"

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
				})
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
			})
		}
	}
}

func TestChallengeRendererConcurrent(t *testing.T) {
	renderer := newChallengeRenderer()
	payload := []byte(`{"challenge_id":"id","challenge":"challenge","difficulty_bits":16,"pass_url":"/__guardian/pass"}`)
	var want bytes.Buffer
	if err := renderer.Render(&want, payload, true, "6", "id"); err != nil {
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
				if err := renderer.Render(&got, payload, true, "6", "id"); err != nil {
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
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
