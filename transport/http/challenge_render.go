// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package httptransport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"strconv"
	"sync"

	"github.com/melroy89/angie-guardian/web"
)

const (
	challengeJSONMarker    = "__guardian_dynamic_json_7f3c9d__"
	challengeURLMarker     = "__guardian_dynamic_url_8a4e2b__"
	challengeRefreshMarker = 987654321
)

// challengeData is the build-time input to the audited HTML template. The
// production hot path does not execute the template: newChallengeRenderer
// executes both branches once and splits the result at these dynamic fields.
type challengeData struct {
	JSON           template.JS
	NoScript       bool
	RefreshSeconds int
	NoJSURL        string
}

// challengeRenderer holds the two immutable compiled forms of the challenge
// page. js is prefix/JSON/suffix. noJS additionally has two refresh values and
// the challenge-specific fallback URL, in the order they occur in the source.
// Every byte still comes from web/challenge.html.tmpl; only its few dynamic
// values are streamed into the gaps per request.
type challengeRenderer struct {
	js          [2][]byte
	noJS        [5][]byte
	jsonWriters *sync.Pool
}

func newChallengeRenderer() challengeRenderer {
	tmpl := template.Must(template.ParseFS(web.FS, "challenge.html.tmpl"))
	jsonWriters := &sync.Pool{
		New: func() any { return new(trailingNewlineWriter) },
	}
	// Seed the common single-request case during construction. Concurrent
	// requests may grow the pool, and a GC may discard idle entries, but neither
	// case retains response writers or adds steady-state request allocations.
	jsonWriters.Put(new(trailingNewlineWriter))
	return challengeRenderer{
		js:          compileChallengeJS(tmpl),
		noJS:        compileChallengeNoJS(tmpl),
		jsonWriters: jsonWriters,
	}
}

func executeChallengeTemplate(tmpl *template.Template, data *challengeData) []byte {
	var out bytes.Buffer
	if err := tmpl.Execute(&out, data); err != nil {
		panic(fmt.Sprintf("compile challenge template: %v", err))
	}
	return out.Bytes()
}

func compileChallengeJS(tmpl *template.Template) [2][]byte {
	body := executeChallengeTemplate(tmpl, &challengeData{JSON: template.JS(challengeJSONMarker)})
	before, after, ok := bytes.Cut(body, []byte(challengeJSONMarker))
	if !ok || bytes.Contains(after, []byte(challengeJSONMarker)) {
		panic("compile challenge template: JSON marker missing or repeated")
	}
	return [2][]byte{bytes.Clone(before), bytes.Clone(after)}
}

func compileChallengeNoJS(tmpl *template.Template) [5][]byte {
	body := executeChallengeTemplate(tmpl, &challengeData{
		JSON:           template.JS(challengeJSONMarker),
		NoScript:       true,
		RefreshSeconds: challengeRefreshMarker,
		NoJSURL:        challengeURLMarker,
	})
	refreshMarker := strconv.Itoa(challengeRefreshMarker)
	if bytes.Count(body, []byte(refreshMarker)) != 2 ||
		bytes.Count(body, []byte(challengeURLMarker)) != 1 ||
		bytes.Count(body, []byte(challengeJSONMarker)) != 1 {
		panic("compile challenge template: dynamic markers missing or repeated")
	}
	markers := [...]string{
		refreshMarker,
		challengeURLMarker,
		refreshMarker,
		challengeJSONMarker,
	}
	var chunks [5][]byte
	rest := body
	for i, marker := range markers {
		before, after, ok := bytes.Cut(rest, []byte(marker))
		if !ok {
			panic(fmt.Sprintf("compile challenge template: marker %q missing", marker))
		}
		chunks[i] = bytes.Clone(before)
		rest = after
	}
	for _, marker := range markers {
		if bytes.Contains(rest, []byte(marker)) {
			panic(fmt.Sprintf("compile challenge template: marker %q repeated", marker))
		}
	}
	chunks[len(chunks)-1] = bytes.Clone(rest)
	return chunks
}

// Render streams a challenge page around an already-encoded JSON payload.
// payload is encoding/json output and therefore already safe for the
// application/json script element.
func (r *challengeRenderer) Render(w io.Writer, payload []byte, noScript bool, refreshSeconds, id string) error {
	if err := r.renderPrefix(w, noScript, refreshSeconds, id); err != nil {
		return err
	}
	if err := writeChallengeBytes(w, payload); err != nil {
		return err
	}
	return r.renderSuffix(w, noScript)
}

// RenderChallenge streams the production payload through encoding/json
// directly into the compiled page gap. Encoder and Marshal produce identical
// bytes before Encoder's framing newline; trailingNewlineWriter removes only
// that final byte, avoiding Marshal's per-request copy into a returned slice.
// The wrapper comes from a concurrency-safe pool because passing it through
// Encoder's io.Writer interface otherwise forces one heap allocation.
func (r *challengeRenderer) RenderChallenge(w io.Writer, data *challengePayload, noScript bool, refreshSeconds string) error {
	if err := r.renderPrefix(w, noScript, refreshSeconds, data.ChallengeID); err != nil {
		return err
	}
	tw := r.jsonWriters.Get().(*trailingNewlineWriter)
	tw.reset(w)
	err := json.NewEncoder(tw).Encode(data)
	if err == nil {
		err = tw.finish()
	}
	// Do not retain the request's ResponseWriter while this entry is idle.
	tw.reset(nil)
	r.jsonWriters.Put(tw)
	if err != nil {
		return err
	}
	return r.renderSuffix(w, noScript)
}

// renderPrefix writes every compiled chunk before the JSON gap. id is
// generated by Guardian; EscapeString is a zero-allocation no-op for both
// supported alphabets and remains safe if a future format introduces an
// HTML-special character.
func (r *challengeRenderer) renderPrefix(w io.Writer, noScript bool, refreshSeconds, id string) error {
	if !noScript {
		return writeChallengeBytes(w, r.js[0])
	}

	writes := []struct {
		b []byte
		s string
	}{
		{b: r.noJS[0]},
		{s: refreshSeconds},
		{b: r.noJS[1]},
		{s: PassPath + "?cid="},
		{s: html.EscapeString(id)},
		{s: "&amp;nojs=1"},
		{b: r.noJS[2]},
		{s: refreshSeconds},
		{b: r.noJS[3]},
	}
	for _, write := range writes {
		var err error
		if write.b != nil {
			err = writeChallengeBytes(w, write.b)
		} else {
			err = writeChallengeString(w, write.s)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *challengeRenderer) renderSuffix(w io.Writer, noScript bool) error {
	if noScript {
		return writeChallengeBytes(w, r.noJS[4])
	}
	return writeChallengeBytes(w, r.js[1])
}

// trailingNewlineWriter retains the most recent byte across writes. finish
// drops it when it is Encoder's framing newline and otherwise forwards it, so
// correctness does not depend on Encoder issuing exactly one Write call.
type trailingNewlineWriter struct {
	w       io.Writer
	tail    [1]byte
	hasTail bool
}

func (w *trailingNewlineWriter) reset(dst io.Writer) {
	w.w = dst
	w.tail[0] = 0
	w.hasTail = false
}

func (w *trailingNewlineWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.hasTail {
		if err := writeChallengeBytes(w.w, w.tail[:]); err != nil {
			return 0, err
		}
	}
	w.tail[0] = p[len(p)-1]
	w.hasTail = true
	if len(p) > 1 {
		if err := writeChallengeBytes(w.w, p[:len(p)-1]); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *trailingNewlineWriter) finish() error {
	if !w.hasTail || w.tail[0] == '\n' {
		return nil
	}
	return writeChallengeBytes(w.w, w.tail[:])
}

func writeChallengeBytes(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}

func writeChallengeString(w io.Writer, s string) error {
	n, err := io.WriteString(w, s)
	if err == nil && n != len(s) {
		return io.ErrShortWrite
	}
	return err
}
