// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package waf

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func loadCommonRules(t *testing.T) *RuleSet {
	t.Helper()
	raw, err := os.ReadFile("../../deploy/rules-common.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := CompileRules(raw, "common rules")
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestCommonRulesDeploymentParity(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/rules-common.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dockerRaw, err := os.ReadFile("../../deploy/docker/rules-common.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, dockerRaw) {
		t.Fatal("native and Docker common rules differ")
	}
}

func TestCommonRulesDisclosureProbes(t *testing.T) {
	rs := loadCommonRules(t)
	for _, group := range []struct {
		id    string
		paths []string
	}{
		{"cloud-credentials-probe", []string{
			"/aws.json", "/google-service-account.json", "/service-account.json",
			"/gcp-credentials.json", "/gcp-key.json", "/creds.json",
			"/sa.json", "/gcp-sa.json", "/credentials.json", "/google-credentials.json",
			"/google-key.json", "/application_default_credentials.json",
			"/firebase-adminsdk.json", "/nested/firebase-key.json", "/SA.JSON/download",
		}},
		{"database-backup-probe", []string{
			"/dump.sql", "/info.php", "/phpinfo.php", "/nested/phpinfo.php.bak",
			"/phpinfo", "/php-info.php", "/phpversion.php", "/_phpinfo.php",
			"/old_phpinfo.php", "/pinfo.php", "/server-info.php.old",
			"/server-status.php.save", "/pinfo.php~", "/_profiler/phpinfo",
			"/_environment", "/webroot/index.php/_environment/details",
		}},
		{"", []string{
			"/info", "/test.php", "/api/data.json", "/credentials.jsonp",
			"/my-service-account.json", "/phpversion.phpx", "/_environmental",
			"/nested/_environment", "/_profiler/phpinformation",
			"/phpinformation", "/phpinfo.txt", "/credentials.json.bak",
		}},
	} {
		for _, path := range group.paths {
			t.Run(path, func(t *testing.T) {
				r := rs.Match(&MatchInput{Path: strings.ToLower(path)})
				if group.id == "" {
					if r != nil {
						t.Fatalf("matched %s, want no match", r.ID)
					}
					return
				}
				if r == nil || r.ID != group.id || r.Action != ActionBlock {
					t.Fatalf("matched %+v, want %s/block", r, group.id)
				}
			})
		}
	}
}

func TestCommonRulesCredentialFilenameBoundaries(t *testing.T) {
	rs := loadCommonRules(t)
	for _, name := range []string{
		"service-account", "sa", "gcp-sa", "credentials", "google-credentials",
		"google-key", "application_default_credentials", "firebase-adminsdk", "firebase-key",
	} {
		for _, prefix := range []string{"", "/nested"} {
			for _, suffix := range []string{"", "/details"} {
				path := prefix + "/" + name + ".json" + suffix
				t.Run(path, func(t *testing.T) {
					assertCommonRule(t, rs, strings.ToUpper(path), "cloud-credentials-probe")
				})
			}
		}
		for _, path := range []string{"/prefix-" + name + ".json", "/" + name + ".jsonp", "/" + name + ".json.bak"} {
			t.Run(path, func(t *testing.T) {
				if r := rs.Match(&MatchInput{Path: path}); r != nil {
					t.Fatalf("matched %s, want no match", r.ID)
				}
			})
		}
	}
}

// These expectations preserve substring coverage as well as exact filenames.
// Replacing keywords with bounded regexes must not silently lose suffixes.
func TestCommonRulesDeduplicationCoverage(t *testing.T) {
	rs := loadCommonRules(t)
	groups := []struct {
		id    string
		paths []string
	}{
		{"dotfile-probe", []string{
			"/.env", "/.env.local", "/.env.production", "/.env.staging",
			"/.env.backup", "/.env.old", "/.env.save", "/.env.dev",
			"/.docker", "/.dockercfg",
		}},
		{"cloud-credentials-probe", []string{
			"/terraform.tfstate", "/terraform.tfstate.backup",
			"/privatekey", "/privatekey.json",
		}},
		{"application-config-probe", []string{
			"/docker-compose", "/docker-compose.override.yml", "/docker-compose.dev.yml",
			"/secrets.yml", "/config/secrets.yml",
		}},
		{"database-backup-probe", []string{"/phpinfo.php", "/info.php"}},
	}
	for _, group := range groups {
		for _, path := range group.paths {
			for _, prefix := range []string{"", "/nested"} {
				for _, suffix := range []string{"", "/details", ".bak", ".old", ".save", "~", ".txt", "123"} {
					path := prefix + path + suffix
					t.Run(path, func(t *testing.T) {
						assertCommonRule(t, rs, path, group.id)
					})
				}
			}
		}
	}

	// Bare phpinfo and profiler routes still require regex coverage after
	// removing the phpinfo.php alternative or the dedicated profiler regex.
	for _, path := range []string{"/phpinfo", "/nested/phpinfo", "/_profiler/phpinfo"} {
		for _, suffix := range []string{"", "/details", ".bak", ".old", ".save", "~"} {
			path := path + suffix
			t.Run(path, func(t *testing.T) {
				assertCommonRule(t, rs, path, "database-backup-probe")
			})
		}
	}
}

func assertCommonRule(t *testing.T, rs *RuleSet, path, id string) {
	t.Helper()
	r := rs.Match(&MatchInput{Path: strings.ToLower(path)})
	if r == nil || r.ID != id || r.Action != ActionBlock {
		t.Fatalf("matched %+v, want %s/block", r, id)
	}
}
