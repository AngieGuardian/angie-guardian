// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package stateless

import (
	"fmt"
	"strings"

	"github.com/melroy89/angie-guardian/core/waf"
	"gopkg.in/yaml.v3"
)

// GuestConfig is the self-contained configuration the WASM guest receives from
// the host (Angie's module config). It carries only the stateless WAF subset,
// with signature rules inline (the guest has no filesystem to read a
// rules_file from). It is a compact analogue of guardian.yaml.
//
// Domains are captured as raw nodes so each domain can be resolved by
// overlaying its own fields on top of a copy of Defaults, exactly like the
// sidecar's per-domain-over-defaults merge (core.Config.finalize). A domain
// inherits every default field it does not itself set.
type GuestConfig struct {
	Defaults GuestDomain          `yaml:"defaults" json:"defaults"`
	Domains  map[string]yaml.Node `yaml:"domains" json:"domains"`

	resolved map[string]*DomainRules
	fallback *DomainRules
}

// GuestDomain is one domain's stateless config in the guest document.
type GuestDomain struct {
	Allowlist ListConfig     `yaml:"allowlist" json:"allowlist"`
	Denylist  ListConfig     `yaml:"denylist" json:"denylist"`
	Honeypot  HoneypotConfig `yaml:"honeypot" json:"honeypot"`
	// Rules is an inline signature rules document (same shape as a rules_file).
	// When present, keyword matching is enabled for the domain.
	Rules yaml.Node `yaml:"rules" json:"rules"`
}

// ParseGuestConfig parses and compiles the guest config document. It accepts
// YAML (a superset of JSON, so a JSON blob works too). Each domain is merged
// over Defaults field-by-field, then allow/deny lists are compiled and inline
// rules turned into a RuleSet, so Evaluate does no parsing on the hot path.
func ParseGuestConfig(raw []byte) (*GuestConfig, error) {
	gc := &GuestConfig{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(gc); err != nil {
		return nil, fmt.Errorf("parse guest config: %w", err)
	}

	// Serialize the defaults once; each domain starts as a copy of them.
	defaultsRaw, err := yaml.Marshal(&gc.Defaults)
	if err != nil {
		return nil, fmt.Errorf("marshal defaults: %w", err)
	}

	fb, err := gc.Defaults.resolve("defaults")
	if err != nil {
		return nil, err
	}
	gc.fallback = fb

	gc.resolved = make(map[string]*DomainRules, len(gc.Domains))
	for host, node := range gc.Domains {
		// Start from defaults, then overlay this domain's own fields so it
		// inherits any field it does not set (sidecar parity).
		gd := GuestDomain{}
		if err := yaml.Unmarshal(defaultsRaw, &gd); err != nil {
			return nil, fmt.Errorf("copy defaults for %s: %w", host, err)
		}
		if node.Kind != 0 && node.Tag != "!!null" {
			if err := decodeStrict(&node, &gd); err != nil {
				return nil, fmt.Errorf("domain %s: %w", host, err)
			}
		}
		r, err := gd.resolve(host)
		if err != nil {
			return nil, err
		}
		gc.resolved[NormalizeHost(host)] = r
	}
	return gc, nil
}

// decodeStrict decodes a yaml.Node into v with unknown-field checking, which
// yaml.Node.Decode does not do on its own. It re-marshals the node and runs it
// through a KnownFields decoder, so a typo in a domain block is a load error
// rather than a silently ignored field.
func decodeStrict(node *yaml.Node, v any) error {
	raw, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	return dec.Decode(v)
}

func (gd *GuestDomain) resolve(host string) (*DomainRules, error) {
	if err := gd.Allowlist.Compile(); err != nil {
		return nil, fmt.Errorf("domain %s allowlist: %w", host, err)
	}
	if err := gd.Denylist.Compile(); err != nil {
		return nil, fmt.Errorf("domain %s denylist: %w", host, err)
	}
	dr := &DomainRules{
		Allowlist: gd.Allowlist,
		Denylist:  gd.Denylist,
		Honeypot:  gd.Honeypot,
	}
	// A zero Rules node marshals as "rules: null" and comes back from the
	// defaults round-trip as an explicit !!null scalar (Kind != 0), so both
	// forms must count as "no rules" or every domain would spuriously enable
	// keyword matching on an empty rule set.
	if gd.Rules.Kind != 0 && gd.Rules.Tag != "!!null" {
		// Re-marshal the inline node and compile it with the shared WAF rules
		// compiler, so the guest and sidecar use one rules format.
		doc := struct {
			Rules yaml.Node `yaml:"rules"`
		}{Rules: gd.Rules}
		out, err := yaml.Marshal(&doc)
		if err != nil {
			return nil, fmt.Errorf("domain %s rules: %w", host, err)
		}
		rs, err := waf.CompileRules(out, "guest:"+host)
		if err != nil {
			return nil, fmt.Errorf("domain %s rules: %w", host, err)
		}
		dr.Rules = rs
		dr.KeywordsEnabled = true
	}
	return dr, nil
}

// Evaluate resolves the domain for a request and runs the stateless pipeline.
// Unknown hosts fall back to the defaults block.
func (gc *GuestConfig) Evaluate(req *RequestContext) Decision {
	r := gc.resolved[NormalizeHost(req.Host)]
	if r == nil {
		r = gc.fallback
	}
	return Evaluate(req, r)
}
