// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package headerexempt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestShapeMatchingIsBoundedAndUnambiguous(t *testing.T) {
	predicates := []PredicateConfig{
		{Header: "Authorization", Prefix: "Bearer ", RequireValue: true, MaxLength: 32},
		{Header: "X-API-Key", RequireValue: true, MaxLength: 8},
		{Header: "X-Widget-Proof", Prefix: "Widget ", RequireValue: true, MaxLength: 32},
	}
	if err := NormalizeAndValidate(predicates); err != nil {
		t.Fatal(err)
	}
	cache, err := NewCache(map[string][]PredicateConfig{VariantKey(predicates): predicates}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cache.Start(time.Hour)
	t.Cleanup(cache.Close)

	tests := []struct {
		name    string
		headers map[string][]string
		outcome Outcome
		match   bool
	}{
		{"authorization example", map[string][]string{"authorization": {"Bearer abc"}}, OutcomeMatched, true},
		{"api key example", map[string][]string{"x-api-key": {"opaque"}}, OutcomeMatched, true},
		{"arbitrary header and scheme", map[string][]string{"x-widget-proof": {"Widget value"}}, OutcomeMatched, true},
		{"missing", nil, OutcomeAbsent, false},
		{"empty", map[string][]string{"x-api-key": {""}}, OutcomeMalformed, false},
		{"prefix only", map[string][]string{"authorization": {"Bearer "}}, OutcomeMalformed, false},
		{"prefix is exact case sensitive", map[string][]string{"authorization": {"bearer abc"}}, OutcomeMalformed, false},
		{"duplicate", map[string][]string{"x-api-key": {"one", "two"}}, OutcomeAmbiguous, false},
		{"folded", map[string][]string{"x-api-key": {"a\nb"}}, OutcomeMalformed, false},
		{"oversized", map[string][]string{"x-api-key": {"123456789"}}, OutcomeOversized, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cache.Match(VariantKey(predicates), Request{Header: func(name string) []string {
				return tc.headers[strings.ToLower(name)]
			}})
			if got.Matched != tc.match || got.Outcome != tc.outcome {
				t.Fatalf("got matched=%v outcome=%s, want %v/%s", got.Matched, got.Outcome, tc.match, tc.outcome)
			}
		})
	}
}

func TestConfigBoundsAndVerifierOptIn(t *testing.T) {
	tests := []struct {
		name string
		cfg  []PredicateConfig
		want string
	}{
		{"too many", make([]PredicateConfig, MaxPredicates+1), "at most"},
		{"invalid header", []PredicateConfig{{Header: "Bad Header"}}, "invalid HTTP header"},
		{"transport host", []PredicateConfig{{Header: "Host"}}, "transport-derived"},
		{"guardian relay", []PredicateConfig{{Header: "x-guardian-ip"}}, "transport-derived"},
		{"oversized max", []PredicateConfig{{Header: "X-Key", MaxLength: MaxHeaderBytes + 1}}, "max_length"},
		{"jwt fields without opt in", []PredicateConfig{{Header: "X-Key", Verifier: VerifierConfig{Issuer: "issuer"}}}, "require type"},
		{"unknown verifier", []PredicateConfig{{Header: "X-Key", Verifier: VerifierConfig{Type: "remote"}}}, "none or jwt_eddsa"},
		{"jwt missing policy", []PredicateConfig{{Header: "X-Key", Verifier: VerifierConfig{Type: VerifierJWTEdDSA, PublicKeys: []string{"key.pem"}}}}, "issuer and audience"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := NormalizeAndValidate(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
	shapeOnly := []PredicateConfig{{Header: "X-Key", RequireValue: true}}
	if err := NormalizeAndValidate(shapeOnly); err != nil {
		t.Fatalf("shape-only config requires no JWT fields: %v", err)
	}
	if shapeOnly[0].MaxLength != defaultMaxLen || shapeOnly[0].Verifier.Type != VerifierNone {
		t.Fatalf("shape-only defaults = %+v", shapeOnly[0])
	}
}

func TestJWTEdDSAVerifierAndPublicKeyReload(t *testing.T) {
	dir := t.TempDir()
	pub1, private1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, private2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "api.pub")
	writePublicKey(t, keyFile, pub1)
	cfg := VerifierConfig{
		Type: VerifierJWTEdDSA, PublicKeys: []string{keyFile}, Issuer: "https://issuer.example",
		Audience: "example-api", MaxLifetime: Duration(15 * time.Minute),
	}
	v := &jwtEdDSAVerifier{config: cfg}
	if err := v.Reload(); err != nil {
		t.Fatal(err)
	}
	req := Request{Host: "API.Example:443", Path: "/api/v1/items"}
	valid := signJWT(t, private1, "api.example", "/api/v1/", cfg.Issuer, cfg.Audience, time.Now(), 5*time.Minute)
	if !v.Verify(valid, req) {
		t.Fatal("valid host/path-bound EdDSA JWT did not verify")
	}
	bareReq := req
	bareReq.Path = "/api/v1"
	if !v.Verify(valid, bareReq) {
		t.Fatal("trailing-slash JWT path binding did not verify its bare path")
	}
	for name, token := range map[string]string{
		"wrong host":          signJWT(t, private1, "other.example", "/api/v1/", cfg.Issuer, cfg.Audience, time.Now(), 5*time.Minute),
		"wrong path":          signJWT(t, private1, "api.example", "/admin/", cfg.Issuer, cfg.Audience, time.Now(), 5*time.Minute),
		"wrong issuer":        signJWT(t, private1, "api.example", "/api/v1/", "other", cfg.Audience, time.Now(), 5*time.Minute),
		"too long":            signJWT(t, private1, "api.example", "/api/v1/", cfg.Issuer, cfg.Audience, time.Now(), 16*time.Minute),
		"unknown key":         signJWT(t, private2, "api.example", "/api/v1/", cfg.Issuer, cfg.Audience, time.Now(), 5*time.Minute),
		"unknown kid":         signJWTWithKID(t, private1, "unknown", "api.example", "/api/v1/", cfg.Issuer, cfg.Audience, time.Now(), 5*time.Minute),
		"algorithm confusion": signHMACJWT(t, pub1, "api.example", "/api/v1/", cfg.Issuer, cfg.Audience),
	} {
		t.Run(name, func(t *testing.T) {
			if v.Verify(token, req) {
				t.Fatal("invalid token verified")
			}
		})
	}

	writePublicKey(t, keyFile, pub2)
	if err := v.Reload(); err != nil {
		t.Fatal(err)
	}
	if v.Verify(valid, req) {
		t.Fatal("token signed by replaced key still verified after reload")
	}
	if token := signJWT(t, private2, "api.example", "/api/v1/", cfg.Issuer, cfg.Audience, time.Now(), 5*time.Minute); !v.Verify(token, req) {
		t.Fatal("token signed by reloaded key did not verify")
	}
}

func TestBoundPathMatchesPrefixAndBarePath(t *testing.T) {
	for _, tc := range []struct {
		name        string
		bound       string
		requestPath string
		want        bool
	}{
		{"prefix descendant", "/api/v1/", "/api/v1/items", true},
		{"prefix bare path", "/api/v1/", "/api/v1", true},
		{"prefix sibling", "/api/v1/", "/api/v10", false},
		{"exact path", "/api/v1", "/api/v1", true},
		{"exact descendant", "/api/v1", "/api/v1/items", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := boundPathMatches(tc.bound, tc.requestPath); got != tc.want {
				t.Fatalf("boundPathMatches(%q, %q) = %v, want %v", tc.bound, tc.requestPath, got, tc.want)
			}
		})
	}
}

func TestPublicKeyLoaderRejectsPrivateMaterial(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPublicKey(file); err == nil || !strings.Contains(err.Error(), "private keys and seeds are rejected") {
		t.Fatalf("private key error = %v", err)
	}
}

func TestCacheHotReloadRetainsLastGoodPublicKeys(t *testing.T) {
	dir := t.TempDir()
	pub1, private1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, private2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "rotating.pub")
	writePublicKey(t, keyFile, pub1)
	predicates := []PredicateConfig{{
		Header: "X-Access-Token", Prefix: "Token ", RequireValue: true, MaxLength: 2048,
		Verifier: VerifierConfig{Type: VerifierJWTEdDSA, PublicKeys: []string{keyFile}, Issuer: "issuer", Audience: "api", MaxLifetime: Duration(15 * time.Minute)},
	}}
	if err := NormalizeAndValidate(predicates); err != nil {
		t.Fatal(err)
	}
	key := VariantKey(predicates)
	cache, err := NewCache(map[string][]PredicateConfig{key: predicates}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	cache.Start(5 * time.Millisecond)
	t.Cleanup(cache.Close)
	oldToken := signJWT(t, private1, "api.test", "/v1/", "issuer", "api", time.Now(), time.Minute)
	newToken := signJWT(t, private2, "api.test", "/v1/", "issuer", "api", time.Now(), time.Minute)
	active := oldToken
	req := Request{Host: "api.test", Path: "/v1/items", Header: func(string) []string { return []string{"Token " + active} }}
	if result := cache.Match(key, req); !result.Matched {
		t.Fatal("initial public key did not match")
	}

	if err := os.WriteFile(keyFile, []byte("not a public key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if result := cache.Match(key, req); !result.Matched {
		t.Fatal("malformed replacement discarded the last good public key")
	}

	writePublicKey(t, keyFile, pub2)
	active = newToken
	deadline := time.Now().Add(2 * time.Second)
	for {
		if result := cache.Match(key, req); result.Matched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("valid replacement public key was not hot-reloaded")
		}
		time.Sleep(5 * time.Millisecond)
	}
	active = oldToken
	if result := cache.Match(key, req); result.Matched {
		t.Fatal("replaced public key remained active after successful reload")
	}
}

func writePublicKey(t testing.TB, file string, key ed25519.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func signJWT(t testing.TB, key ed25519.PrivateKey, host, boundPath, issuer, audience string, issued time.Time, lifetime time.Duration) string {
	return signJWTWithKID(t, key, "", host, boundPath, issuer, audience, issued, lifetime)
}

func signJWTWithKID(t testing.TB, key ed25519.PrivateKey, kid, host, boundPath, issuer, audience string, issued time.Time, lifetime time.Duration) string {
	t.Helper()
	claims := jwtClaims{
		GuardianHost: host, GuardianPath: boundPath,
		Issuer: issuer, Audience: jwt.ClaimStrings{audience}, IssuedAt: jwt.NewNumericDate(issued),
		NotBefore: jwt.NewNumericDate(issued.Add(-time.Second)), ExpiresAt: jwt.NewNumericDate(issued.Add(lifetime)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signHMACJWT(t testing.TB, secret []byte, host, boundPath, issuer, audience string) string {
	t.Helper()
	now := time.Now()
	claims := jwtClaims{
		GuardianHost: host, GuardianPath: boundPath,
		Issuer: issuer, Audience: jwt.ClaimStrings{audience}, IssuedAt: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func BenchmarkShapeMatch(b *testing.B) {
	predicates := []PredicateConfig{
		{Header: "Authorization", Prefix: "Bearer ", RequireValue: true, MaxLength: 2048},
		{Header: "X-API-Key", RequireValue: true, MaxLength: 256},
		{Header: "X-Widget-Proof", Prefix: "Widget ", RequireValue: true, MaxLength: 512},
	}
	if err := NormalizeAndValidate(predicates); err != nil {
		b.Fatal(err)
	}
	key := VariantKey(predicates)
	cache, err := NewCache(map[string][]PredicateConfig{key: predicates}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		b.Fatal(err)
	}
	cache.Start(time.Hour)
	b.Cleanup(cache.Close)
	value := []string{"Widget opaque"}
	req := Request{Host: "example.test", Path: "/api/v1/items", Header: func(name string) []string {
		if name == "X-Widget-Proof" {
			return value
		}
		return nil
	}}
	if got := cache.Match(key, req); !got.Matched {
		b.Fatal("sanity: configured shape did not match")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		cache.Match(key, req)
	}
}

func BenchmarkJWTEdDSAVerify(b *testing.B) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	keyFile := filepath.Join(b.TempDir(), "api.pub")
	writePublicKey(b, keyFile, public)
	cfg := VerifierConfig{
		Type: VerifierJWTEdDSA, PublicKeys: []string{keyFile}, Issuer: "issuer",
		Audience: "api", MaxLifetime: Duration(15 * time.Minute),
	}
	v := &jwtEdDSAVerifier{config: cfg}
	if err := v.Reload(); err != nil {
		b.Fatal(err)
	}
	raw := signJWT(b, private, "api.test", "/v1/", cfg.Issuer, cfg.Audience, time.Now(), time.Minute)
	req := Request{Host: "api.test", Path: "/v1/items"}
	if !v.Verify(raw, req) {
		b.Fatal("sanity: valid JWT did not verify")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		v.Verify(raw, req)
	}
}
