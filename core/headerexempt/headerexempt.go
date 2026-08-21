// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package headerexempt classifies explicitly configured request-header shapes
// that may skip proof-of-work. It does not authenticate or authorize requests.
package headerexempt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/melroy89/angie-guardian/core/stateless"
	"gopkg.in/yaml.v3"
)

const (
	MaxPredicates  = 8
	MaxHeaderBytes = 4096
	MaxPublicKeys  = 2
	defaultMaxLen  = 1024
)

const (
	VerifierNone     = "none"
	VerifierJWTEdDSA = "jwt_eddsa"
)

// PredicateConfig is one generic, configuration-driven header shape.
type PredicateConfig struct {
	Header       string         `yaml:"header" json:"header"`
	Prefix       string         `yaml:"prefix" json:"prefix"`
	RequireValue bool           `yaml:"require_value" json:"require_value"`
	MaxLength    int            `yaml:"max_length" json:"max_length"`
	Verifier     VerifierConfig `yaml:"verifier" json:"verifier"`
}

// VerifierConfig opts one predicate into an offline verifier. The zero value
// is deliberately shape-only.
type VerifierConfig struct {
	Type        string   `yaml:"type" json:"type"`
	PublicKeys  []string `yaml:"public_keys" json:"public_keys"`
	Issuer      string   `yaml:"issuer" json:"issuer"`
	Audience    string   `yaml:"audience" json:"audience"`
	MaxLifetime Duration `yaml:"max_lifetime" json:"max_lifetime"`
}

// Duration is kept local so this leaf package does not import core.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

func (d Duration) Std() time.Duration { return time.Duration(d) }

// NormalizeAndValidate applies defaults and rejects ambiguous or unbounded
// configurations. It does not read verifier key files.
func NormalizeAndValidate(predicates []PredicateConfig) error {
	if len(predicates) > MaxPredicates {
		return fmt.Errorf("header_exemptions supports at most %d predicates, got %d", MaxPredicates, len(predicates))
	}
	for i := range predicates {
		p := &predicates[i]
		where := fmt.Sprintf("header_exemptions[%d]", i)
		if !validHeaderName(p.Header) {
			return fmt.Errorf("%s.header: invalid HTTP header name %q", where, p.Header)
		}
		nameLower := strings.ToLower(p.Header)
		if nameLower == "host" || strings.HasPrefix(nameLower, "x-guardian-") {
			return fmt.Errorf("%s.header: %q is transport-derived, not an end-to-end client credential header", where, p.Header)
		}
		if hasInvalidFieldValueByte(p.Prefix) {
			return fmt.Errorf("%s.prefix: control characters are not allowed", where)
		}
		if p.MaxLength == 0 {
			p.MaxLength = defaultMaxLen
		}
		if p.MaxLength < 1 || p.MaxLength > MaxHeaderBytes {
			return fmt.Errorf("%s.max_length must be 1..%d, got %d", where, MaxHeaderBytes, p.MaxLength)
		}
		if len(p.Prefix) > p.MaxLength {
			return fmt.Errorf("%s.prefix is longer than max_length", where)
		}
		v := &p.Verifier
		switch v.Type {
		case "", VerifierNone:
			v.Type = VerifierNone
			if len(v.PublicKeys) != 0 || v.Issuer != "" || v.Audience != "" || v.MaxLifetime != 0 {
				return fmt.Errorf("%s.verifier: jwt fields require type jwt_eddsa", where)
			}
		case VerifierJWTEdDSA:
			if len(v.PublicKeys) < 1 || len(v.PublicKeys) > MaxPublicKeys {
				return fmt.Errorf("%s.verifier.public_keys must contain 1..%d files", where, MaxPublicKeys)
			}
			if slices.Contains(v.PublicKeys, "") || (len(v.PublicKeys) == 2 && v.PublicKeys[0] == v.PublicKeys[1]) {
				return fmt.Errorf("%s.verifier.public_keys must contain distinct non-empty files", where)
			}
			if strings.TrimSpace(v.Issuer) == "" || strings.TrimSpace(v.Audience) == "" {
				return fmt.Errorf("%s.verifier issuer and audience are required for jwt_eddsa", where)
			}
			if v.MaxLifetime.Std() <= 0 || v.MaxLifetime.Std() > 24*time.Hour {
				return fmt.Errorf("%s.verifier.max_lifetime must be > 0 and <= 24h", where)
			}
		default:
			return fmt.Errorf("%s.verifier.type must be none or jwt_eddsa, got %q", where, v.Type)
		}
	}
	return nil
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func hasInvalidFieldValueByte(s string) bool {
	for i := range len(s) {
		if s[i] == 0x7f || (s[i] < 0x20 && s[i] != '\t') {
			return true
		}
	}
	return false
}

// VariantKey is stable for one effective predicate list.
func VariantKey(predicates []PredicateConfig) string {
	b, _ := json.Marshal(predicates)
	return string(b)
}

// Request is the bounded request view needed by matchers and verifiers.
type Request struct {
	Host   string
	Path   string
	Header func(string) []string
}

type Outcome string

const (
	OutcomeMatched        Outcome = "matched"
	OutcomeAbsent         Outcome = "absent"
	OutcomeMalformed      Outcome = "malformed"
	OutcomeAmbiguous      Outcome = "ambiguous"
	OutcomeOversized      Outcome = "oversized"
	OutcomeVerifierFailed Outcome = "verifier_failed"
)

type Result struct {
	Matched  bool
	Outcome  Outcome
	Verifier string
}

type verifier interface {
	Verify(token string, req Request) bool
	Reload() error
}

type predicate struct {
	config   PredicateConfig
	verifier verifier
}

type matcher struct{ predicates []predicate }

// Cache owns immutable matchers and hot-reloadable public verification keys.
type Cache struct {
	matchers map[string]*matcher
	log      *slog.Logger
	stop     chan struct{}
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	started  bool
	closed   bool
}

// NewCache validates and loads every configured public key before returning.
func NewCache(variants map[string][]PredicateConfig, log *slog.Logger) (*Cache, error) {
	c := &Cache{matchers: make(map[string]*matcher, len(variants)), log: log, stop: make(chan struct{}), done: make(chan struct{})}
	for key, configs := range variants {
		m := &matcher{predicates: make([]predicate, len(configs))}
		for i, cfg := range configs {
			m.predicates[i].config = cfg
			if cfg.Verifier.Type == VerifierJWTEdDSA {
				v := &jwtEdDSAVerifier{config: cfg.Verifier}
				if err := v.Reload(); err != nil {
					return nil, fmt.Errorf("header_exemptions[%d] jwt_eddsa: %w", i, err)
				}
				m.predicates[i].verifier = v
			}
		}
		c.matchers[key] = m
	}
	return c, nil
}

func (c *Cache) Start(interval time.Duration) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.started || c.closed {
		c.mu.Unlock()
		return
	}
	c.started = true
	c.mu.Unlock()
	go func() {
		defer close(c.done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				for _, m := range c.matchers {
					for _, p := range m.predicates {
						if p.verifier != nil {
							if err := p.verifier.Reload(); err != nil {
								c.log.Warn("header exemption public-key reload failed; retaining last good keys", "err", err)
							}
						}
					}
				}
			case <-c.stop:
				return
			}
		}
	}()
}

func (c *Cache) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	started := c.started
	c.mu.Unlock()
	if !started {
		close(c.done)
		return
	}
	c.once.Do(func() { close(c.stop) })
	<-c.done
}

// Match evaluates at most the configured maximum number of predicates. Header
// names are case-insensitive at the transport getter; prefixes are exact,
// case-sensitive byte strings.
func (c *Cache) Match(key string, req Request) Result {
	if c == nil || req.Header == nil {
		return Result{Outcome: OutcomeAbsent, Verifier: VerifierNone}
	}
	m := c.matchers[key]
	if m == nil {
		return Result{Outcome: OutcomeAbsent, Verifier: VerifierNone}
	}
	best := Result{Outcome: OutcomeAbsent, Verifier: VerifierNone}
	for _, p := range m.predicates {
		values := req.Header(p.config.Header)
		if len(values) == 0 {
			continue
		}
		verifierType := p.config.Verifier.Type
		if len(values) != 1 {
			best = stronger(best, Result{Outcome: OutcomeAmbiguous, Verifier: verifierType})
			continue
		}
		value := values[0]
		if len(value) > p.config.MaxLength {
			best = stronger(best, Result{Outcome: OutcomeOversized, Verifier: verifierType})
			continue
		}
		if value == "" || hasInvalidFieldValueByte(value) || !strings.HasPrefix(value, p.config.Prefix) {
			best = stronger(best, Result{Outcome: OutcomeMalformed, Verifier: verifierType})
			continue
		}
		token := value[len(p.config.Prefix):]
		if p.config.RequireValue && token == "" {
			best = stronger(best, Result{Outcome: OutcomeMalformed, Verifier: verifierType})
			continue
		}
		if p.verifier != nil && !p.verifier.Verify(token, req) {
			best = stronger(best, Result{Outcome: OutcomeVerifierFailed, Verifier: verifierType})
			continue
		}
		return Result{Matched: true, Outcome: OutcomeMatched, Verifier: verifierType}
	}
	return best
}

func stronger(a, b Result) Result {
	if outcomeRank(b.Outcome) > outcomeRank(a.Outcome) {
		return b
	}
	return a
}

func outcomeRank(outcome Outcome) int {
	switch outcome {
	case OutcomeOversized:
		return 4
	case OutcomeAmbiguous:
		return 3
	case OutcomeVerifierFailed:
		return 2
	case OutcomeMalformed:
		return 1
	default:
		return 0
	}
}

type jwtClaims struct {
	GuardianHost string `json:"guardian_host"`
	GuardianPath string `json:"guardian_path"`
	jwt.RegisteredClaims
}

type verificationKey struct {
	id  string
	key ed25519.PublicKey
}

type keySet struct{ keys []verificationKey }

type jwtEdDSAVerifier struct {
	config VerifierConfig
	keys   atomic.Pointer[keySet]
}

func (v *jwtEdDSAVerifier) Reload() error {
	set := &keySet{keys: make([]verificationKey, 0, len(v.config.PublicKeys))}
	for _, file := range v.config.PublicKeys {
		key, err := loadPublicKey(file)
		if err != nil {
			return err
		}
		fingerprint := sha256.Sum256(key)
		set.keys = append(set.keys, verificationKey{
			id: base64.RawURLEncoding.EncodeToString(fingerprint[:]), key: key,
		})
	}
	v.keys.Store(set)
	return nil
}

func loadPublicKey(file string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", file, err)
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("%s: expected exactly one PEM PUBLIC KEY block; private keys and seeds are rejected", file)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: parse public key: %w", file, err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s: key is not an Ed25519 public key", file)
	}
	return slices.Clone(key), nil
}

func (v *jwtEdDSAVerifier) Verify(raw string, req Request) bool {
	set := v.keys.Load()
	if set == nil {
		return false
	}
	for _, key := range set.keys {
		claims := &jwtClaims{}
		_, err := jwt.ParseWithClaims(raw, claims,
			func(t *jwt.Token) (any, error) {
				if t.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
					return nil, errors.New("unexpected JWT algorithm")
				}
				if kid, present := t.Header["kid"]; present {
					value, ok := kid.(string)
					if !ok || value != key.id {
						return nil, errors.New("unknown JWT key id")
					}
				}
				return key.key, nil
			},
			jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithIssuer(v.config.Issuer),
			jwt.WithAudience(v.config.Audience),
		)
		if err != nil || claims.IssuedAt == nil || claims.ExpiresAt == nil {
			continue
		}
		if !claims.ExpiresAt.Time.After(claims.IssuedAt.Time) || claims.ExpiresAt.Time.Sub(claims.IssuedAt.Time) > v.config.MaxLifetime.Std() {
			continue
		}
		if normalizeHost(claims.GuardianHost) != normalizeHost(req.Host) || !boundPathMatches(claims.GuardianPath, req.Path) {
			continue
		}
		return true
	}
	return false
}

func normalizeHost(host string) string {
	return stateless.NormalizeHost(host)
}

func boundPathMatches(bound, requestPath string) bool {
	if bound == "" || bound[0] != '/' || strings.ContainsAny(bound, "?#") {
		return false
	}
	prefix := strings.HasSuffix(bound, "/")
	if stateless.NormalizePath(bound) != bound {
		return false
	}
	if prefix {
		return strings.HasPrefix(requestPath, bound) || requestPath == strings.TrimSuffix(bound, "/")
	}
	return requestPath == bound
}
