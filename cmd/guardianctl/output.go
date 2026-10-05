// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
)

// Reports can contain attacker-controlled reasons, paths, hosts and UAs.
func terminalSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
}

func render(out io.Writer, asJSON bool, command string, result map[string]any) error {
	if asJSON {
		raw, err := json.Marshal(result, jsontext.WithIndent("  "))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(raw))
		return err
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	switch command {
	case "diagnostics capture":
		fmt.Fprintf(w, "Saved %s (%v bytes)\n", safeValue(result["path"]), safeValue(result["bytes"]))
	case "diagnostics status":
		tree(w, result, "")
		if result["enabled"] == false {
			fmt.Fprintln(w, "Set admin.diagnostics_enabled: true and restart Guardian to enable captures.")
		}
	case "block":
		fmt.Fprintf(w, "Blocked %v\nReason: %v\nTTL: %v\n", safeValue(result["ip"]), safeValue(result["reason"]), safeValue(result["ttl"]))
	case "unblock":
		fmt.Fprintf(w, "Unblocked %v\n", safeValue(result["ip"]))
		tree(w, result["reset"], "reset")
		if reset, ok := result["reset"].(map[string]any); ok && reset["incomplete"] == true {
			fmt.Fprintln(w, "WARNING: counter reset incomplete; inspect store health before retrying.")
		}
	case "status":
		state := "not blocked"
		if result["blocked"] == true {
			state = "blocked"
		}
		fmt.Fprintf(w, "%v: %s\n", safeValue(result["ip"]), state)
		tree(w, result, "")
	case "list":
		fmt.Fprintf(w, "Active blocks: %v\n", safeValue(result["count"]))
		if result["complete"] != true {
			fmt.Fprintln(w, "WARNING: incomplete list; more blocks may exist (increase --limit, max 10000).")
		}
		rows(w, result["blocks"], []string{"ip", "reason", "expires_at"})
	case "decisions":
		fmt.Fprintf(w, "Recent decisions: %v (retained in-process history)\n", safeValue(result["count"]))
		if result["truncated"] == true {
			fmt.Fprintln(w, "WARNING: results truncated; increase --limit (max 10000).")
		}
		tree(w, result["window"], "window")
		rows(w, result["decisions"], []string{"time", "ip", "action", "reason", "host", "uri"})
	case "offenders":
		fmt.Fprintf(w, "Top offenders (recent non-allow window: %v)\n", safeValue(result["window"]))
		rows(w, result["ips"], []string{"ip", "count", "country", "asn", "as_org"})
	case "health":
		for _, name := range []string{"liveness", "readiness"} {
			probe, _ := result[name].(map[string]any)
			state := "FAILED"
			if probe["ok"] == true {
				state = "ok"
			}
			fmt.Fprintf(w, "%s:\t%s\n", name, state)
			tree(w, probe["response"], name+".response")
			if probe["error"] != nil {
				fmt.Fprintf(w, "%s.error:\t%s\n", name, safeValue(probe["error"]))
			}
		}
	case "reload":
		if result["reloaded"] == true {
			fmt.Fprintln(w, "Configuration reloaded.")
		} else if result["reloadable"] == true {
			fmt.Fprintln(w, "Preflight passed: configuration is reloadable (no changes applied).")
		} else {
			fmt.Fprintln(w, "Preflight failed: restart required.")
			tree(w, result["restart_required"], "restart_required")
		}
	default:
		if command == "stats" && result["blocks_complete"] == false {
			fmt.Fprintln(w, "WARNING: active block count is incomplete; -1 means the mirror has not seeded.")
		}
		tree(w, result, "")
	}
	return w.Flush()
}

func safeValue(v any) string {
	if v == nil {
		return "-"
	}
	return terminalSafe(fmt.Sprint(v))
}
func rows(w io.Writer, value any, columns []string) {
	fmt.Fprintln(w, strings.ToUpper(strings.Join(columns, "\t")))
	list, _ := value.([]any)
	if len(list) == 0 {
		fmt.Fprintln(w, "(none)")
		return
	}
	for _, v := range list {
		row, _ := v.(map[string]any)
		values := make([]string, len(columns))
		for i, key := range columns {
			values[i] = safeValue(row[key])
		}
		fmt.Fprintln(w, strings.Join(values, "\t"))
	}
}
func tree(w io.Writer, v any, prefix string) {
	switch value := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			fmt.Fprintf(w, "%s:\t(none)\n", terminalSafe(prefix))
		}
		for _, key := range keys {
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			tree(w, value[key], path)
		}
	case []any:
		if len(value) == 0 {
			fmt.Fprintf(w, "%s:\t(none)\n", terminalSafe(prefix))
		}
		for i, item := range value {
			tree(w, item, fmt.Sprintf("%s[%d]", prefix, i))
		}
	default:
		fmt.Fprintf(w, "%s:\t%s\n", terminalSafe(prefix), safeValue(v))
	}
}
