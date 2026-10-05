// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// guardianctl operates the running daemon through its admin listener.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/melroy89/angie-guardian/internal/duration"
)

var version = "dev"

const help = `Usage: guardianctl [options] <command> [options]

Commands:
  block <ip> [--reason text] [--ttl duration]  Block an IP (default: admin, 24h)
  unblock <ip> [--keep-backoff]               Unblock and clear triggering counters
  status <ip>                               Show an IP's behavioural block status
  list [--limit n]                          List active blocks (default 1000; max 10000)
  health                                    Check liveness and store readiness
  stats                                     Show operational statistics
  decisions [--ip ip] [--limit n]            Show recent decisions (default 50)
  offenders                                 Show top recent offenders
  config show                               Show the running redacted configuration
  reload [--check]                           Preflight, then apply (check: no writes)
  diagnostics status                       Show capture availability and cooldown
  diagnostics capture --out path           Capture and download goroutine profiles

Shared options (may appear before or after the command):
  --config path      Guardian config (default /etc/guardian/guardian.yaml)
  --endpoint URL     Direct admin listener; overrides admin.listen
  --token-file path  Read an existing token; overrides configured credentials
  --timeout duration Request timeout (default 5s; capture 30s)
  --json             Machine-readable output
  --help             Show help (also: <command> --help)
  --version          Show version

Credentials: --token-file, then admin.token, ADMIN_TOKEN, admin.token_file.
Unblock does not remove static denylist entries or override WAF deny rules.
Exit codes: 0 success, 1 API/download/reload/readiness failure, 2 input/config/destination error,
            3 authentication failure, 4 connection/timeout failure.
`

type options struct {
	config, endpoint, tokenFile string
	destination                 string
	timeout                     time.Duration
	json, check, keepBackoff    bool
	reason, ttl, ip             string
	limit                       int
}

type cliError struct {
	code    int
	message string
}

func (e *cliError) Error() string { return e.message }
func fail(code int, format string, args ...any) error {
	return &cliError{code, fmt.Sprintf(format, args...)}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(args []string, out, errOut io.Writer) int {
	return runContext(context.Background(), args, out, errOut)
}

func runContext(ctx context.Context, args []string, out, errOut io.Writer) int {
	err := execute(ctx, args, out)
	if err == nil {
		return 0
	}
	fmt.Fprintln(errOut, "guardianctl:", err)
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.code
	}
	return 1
}

// Split known option values from operands so Go's flag parser can accept
// flags after an IP as well as before it. Values are never echoed in errors.
func reorder(args []string, fs *flag.FlagSet) ([]string, error) {
	var flags, operands []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			operands = append(operands, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			operands = append(operands, a)
			continue
		}
		name, _, equals := strings.Cut(strings.TrimLeft(a, "-"), "=")
		f := fs.Lookup(name)
		if f == nil {
			return nil, fail(2, "unknown option --%s; use --help", name)
		}
		flags = append(flags, a)
		boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
		if !equals && !(ok && boolean.IsBoolFlag()) {
			i++
			if i == len(args) {
				return nil, fail(2, "--%s requires a value", name)
			}
			flags = append(flags, args[i])
		}
	}
	return append(flags, operands...), nil
}

func execute(ctx context.Context, args []string, out io.Writer) error {
	o := options{config: "/etc/guardian/guardian.yaml", timeout: 5 * time.Second}
	fs := flag.NewFlagSet("guardianctl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.config, "config", o.config, "")
	fs.StringVar(&o.endpoint, "endpoint", "", "")
	fs.StringVar(&o.tokenFile, "token-file", "", "")
	fs.DurationVar(&o.timeout, "timeout", o.timeout, "")
	fs.BoolVar(&o.json, "json", false, "")
	var helpFlag, versionFlag bool
	fs.BoolVar(&helpFlag, "help", false, "")
	fs.BoolVar(&helpFlag, "h", false, "")
	fs.BoolVar(&versionFlag, "version", false, "")
	// First discover the command, skipping shared option values.
	command := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			command = a
			break
		}
		name, _, equals := strings.Cut(strings.TrimLeft(a, "-"), "=")
		f := fs.Lookup(name)
		if f == nil {
			return fail(2, "unknown option --%s; use --help", name)
		}
		b, ok := f.Value.(interface{ IsBoolFlag() bool })
		if !equals && !(ok && b.IsBoolFlag()) {
			i++
		}
	}
	switch command {
	case "block":
		fs.StringVar(&o.reason, "reason", "", "")
		fs.StringVar(&o.ttl, "ttl", "", "")
	case "unblock":
		fs.BoolVar(&o.keepBackoff, "keep-backoff", false, "")
	case "list":
		fs.IntVar(&o.limit, "limit", 1000, "")
	case "decisions":
		fs.IntVar(&o.limit, "limit", 50, "")
		fs.StringVar(&o.ip, "ip", "", "")
	case "diagnostics":
		fs.StringVar(&o.destination, "out", "", "")
	case "reload":
		fs.BoolVar(&o.check, "check", false, "")
	case "", "help", "status", "health", "stats", "offenders", "config":
	default:
		return fail(2, "unknown command %q; use --help", command)
	}
	ordered, err := reorder(args, fs)
	if err != nil {
		return err
	}
	if err := fs.Parse(ordered); err != nil {
		return fail(2, "invalid option value; use --help")
	}
	if helpFlag || command == "help" || len(args) == 0 {
		_, err := io.WriteString(out, help)
		return err
	}
	if versionFlag {
		_, err := fmt.Fprintln(out, "guardianctl", version)
		return err
	}
	operands := fs.Args()
	if len(operands) == 0 {
		return fail(2, "a command is required; use --help")
	}
	method, path := "GET", ""
	var body any
	var targetIP string
	switch command {
	case "block", "unblock", "status":
		if len(operands) != 2 {
			return fail(2, "%s requires one IP address", command)
		}
		ip, err := canonicalIP(operands[1])
		if err != nil {
			return err
		}
		targetIP = ip
		path = "/admin/blocks/" + ip
		if command == "block" {
			if o.ttl != "" {
				d, err := duration.Parse(o.ttl)
				if err != nil || d <= 0 || d > duration.Year {
					return fail(2, "ttl must be a positive duration of at most 1y")
				}
			}
			if len(o.reason) > 200 || strings.ContainsFunc(o.reason, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
				return fail(2, "reason must be at most 200 bytes without control characters")
			}
			method, body = "PUT", map[string]string{"reason": o.reason, "ttl": o.ttl}
		} else if command == "unblock" {
			method = "DELETE"
			path += "?reset_backoff=" + strconv.FormatBool(!o.keepBackoff)
		}
	case "diagnostics":
		if len(operands) != 2 || (operands[1] != "status" && operands[1] != "capture") {
			return fail(2, "use diagnostics status or diagnostics capture --out <path>")
		}
		if operands[1] == "status" && o.destination != "" {
			return fail(2, "--out is only supported by diagnostics capture")
		}
		if operands[1] == "capture" {
			if o.destination == "" || o.destination == "-" {
				return fail(2, "diagnostics capture requires --out <file> (stdout is not supported)")
			}
			explicitTimeout := false
			fs.Visit(func(f *flag.Flag) {
				if f.Name == "timeout" {
					explicitTimeout = true
				}
			})
			if !explicitTimeout {
				o.timeout = 30 * time.Second
			}
		}
		path = diagnosticsPath
	case "config":
		if len(operands) != 2 || operands[1] != "show" {
			return fail(2, "use config show to read the running redacted configuration")
		}
		path = "/admin/config"
	default:
		if len(operands) != 1 {
			return fail(2, "%s does not accept positional arguments", command)
		}
		switch command {
		case "list":
			if o.limit < 1 || o.limit > 10000 {
				return fail(2, "limit must be from 1 through 10000")
			}
			path = "/admin/blocks?limit=" + strconv.Itoa(o.limit)
		case "decisions":
			if o.limit < 1 || o.limit > 10000 {
				return fail(2, "limit must be from 1 through 10000")
			}
			path = "/admin/decisions?limit=" + strconv.Itoa(o.limit)
			if o.ip != "" {
				ip, err := canonicalIP(o.ip)
				if err != nil {
					return err
				}
				path += "&ip=" + ip
			}
		case "stats", "offenders":
			path = "/admin/" + command
		case "reload":
			path = "/admin/reload/preflight"
		case "health":
		default:
			return fail(2, "a command is required; use --help")
		}
	}
	if o.timeout <= 0 || o.timeout > time.Minute {
		return fail(2, "timeout must be positive and at most 1m")
	}
	c, err := newClient(o, command != "health")
	if err != nil {
		return err
	}
	c.ctx = ctx
	defer c.http.CloseIdleConnections()
	if command == "diagnostics" {
		return c.diagnostics(operands[1], o, out)
	}
	if command == "health" {
		return c.health(out, o.json)
	}
	result, err := c.request(method, path, body)
	if err != nil {
		return err
	}
	if command == "block" || command == "unblock" || command == "status" {
		blocked, ok := result["blocked"].(bool)
		if !ok || result["ip"] != targetIP || (command == "block" && !blocked) || (command == "unblock" && blocked) {
			return fail(1, "invalid block response: expected matching IP and block state")
		}
	}
	if command == "reload" {
		reloadable, ok := result["reloadable"].(bool)
		if !ok {
			return fail(1, "invalid preflight response: missing reloadable")
		}
		if !reloadable {
			if err := render(out, o.json, command, result); err != nil {
				return err
			}
			return fail(1, "reload rejected; restart required")
		}
		if !o.check {
			result, err = c.request("POST", "/admin/reload", nil)
			if err != nil {
				return err
			}
			if result["reloaded"] != true {
				return fail(1, "invalid reload response: application was not confirmed")
			}
		}
	}
	return render(out, o.json, command, result)
}

func canonicalIP(raw string) (string, error) {
	a, err := netip.ParseAddr(raw)
	if err != nil || a.Zone() != "" {
		return "", fail(2, "expected an IPv4 or IPv6 address without a zone")
	}
	return a.Unmap().String(), nil
}
