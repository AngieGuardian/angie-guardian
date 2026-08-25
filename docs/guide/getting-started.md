# Getting Started

This guide installs a pinned, prebuilt Guardian release on a Linux host, wires
it into an existing Angie site, and verifies the complete request path. The
primary path needs no repository checkout or Go toolchain.

## Prerequisites

- [Angie](https://en.angie.software/) already serving the site you want to
  protect.
- A Linux `amd64` (`x86_64`) or `arm64` (`aarch64`) host.
- Root or `sudo` access, plus `wget` and `tar`.

Running Guardian in containers instead? Follow the
[production Docker guide](/guide/production#docker). The repository provides a
production-ready reference Compose stack in
[`deploy/docker/compose.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/docker/compose.yaml),
which wires Angie, the `guardiand` sidecar, and an upstream backend together.

## 1. Install a prebuilt release

### One-command Debian/Ubuntu install

On a Debian or Ubuntu host that already has Angie installed, this installer
downloads the latest GitHub release, pins that run to the release's exact
version, verifies `SHA256SUMS`, installs and starts `guardiand`, and places
five Angie snippets in `/etc/angie`: three required Guardian integration
snippets and two optional Angie hardening snippets.

```sh
curl -fsSL https://raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh | sudo bash
```

It supports `amd64` and `arm64` systemd hosts. On repeat runs it updates the
binary but preserves `/etc/systemd/system/guardiand.service`,
`/etc/guardian/guardian.yaml`, starter rules, existing Angie snippets, and all
state under `/var/lib/guardian`. For the starter rules file, systemd unit, and
the five Angie snippets, the installer compares SHA-256 checksums; if a local
file differs from the release, it prints an **ACTION REQUIRED** notice and
leaves the file untouched so you can review and update it yourself. This keeps
local WAF rules, `Environment=` settings, and Angie customizations intact.

The installer deliberately does **not** edit any Angie vhost or reload Angie:
review the example policy and replace its `example.com` domains, define the
`upstream guardian` in your top-level Angie configuration (`/etc/angie/angie.conf`),
include the Guardian baseline, and then add the server-level snippets to each
protected `server {}` block. Validate and reload Angie yourself:

```nginx
include angie-guardian-limits.conf;

upstream guardian {
    # TCP works for every Angie worker user.
    server 127.0.0.1:8071;
    # Host-local alternative: replace the line above if you prefer the socket:
    # server unix:/run/guardian/guardian.sock max_conns=512;
    keepalive 64;
}
```

The socket defaults to `guardian:guardian` mode `0660`. To use it, either add
the worker user named by Angie's top-level `user` directive to the `guardian`
group, or set `socket_mode: "0666"` in `/etc/guardian/guardian.yaml`, validate
the file, and restart Guardian. The latter needs no Angie user change, but it
allows every local process to connect and forge the client-identity headers
Guardian trusts from Angie. The worker user is not necessarily `www-data`;
native installations may use `angie`, while migrated or custom configurations
may name another account.

**Place this once in Angie's top-level configuration (`/etc/angie/angie.conf` or a file it includes).**

For each protected `server {}` block, add:

```nginx
include angie-guardian.conf;
include angie-guardian-location.conf;
```

Validate the completed Angie configuration, then reload it. Restart Angie
instead only when you changed its worker's group membership:

```sh
sudo angie -t
sudo systemctl reload angie
# sudo systemctl restart angie # if its worker group membership changed
```

Use the manual installation below when you need a particular release version,
a non-Debian/Ubuntu host, or want to inspect the archive before installation.

Choose a pinned version on the
[GitHub releases page](https://github.com/AngieGuardian/angie-guardian/releases).
Most Intel and AMD servers use `linux-amd64`; an
ARM server uses `linux-arm64` instead. For example, to download and extract
version `1.4.0` for amd64:

```sh
wget https://github.com/AngieGuardian/angie-guardian/releases/download/1.4.0/angie-guardian-1.4.0-linux-amd64.tar.gz
tar -xzf angie-guardian-1.4.0-linux-amd64.tar.gz
cd angie-guardian-1.4.0-linux-amd64
```

Substitute the version you selected. On ARM64, also replace `amd64` with `arm64` in the URL,
archive name, and directory name.

The extracted directory contains `guardiand`, the `guardian-train` and
`guardian-loadtest` companion tools, the optional `guardian.wasm`, the
canonical [`guardian.example.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/guardian.example.yaml), and the complete `deploy/` directory. The
installation below uses the binary, systemd unit, Angie snippets, and starter
rules directly from that directory.

Install the daemon and create its dedicated service identity:

```sh
sudo install -Dm755 guardiand /usr/local/bin/guardiand
getent group guardian >/dev/null || sudo groupadd --system guardian
id guardian >/dev/null 2>&1 || sudo useradd --system --gid guardian \
  --home-dir /var/lib/guardian --shell /usr/sbin/nologin guardian
```

### Verify the download

Every release publishes a `SHA256SUMS` file next to the archives, listing the
SHA-256 digest of each one. Releases from 1.0.0 onward also publish an armored
detached signature (`SHA256SUMS.asc`) and the release public key
(`RELEASE-KEY.asc`). Verify the key fingerprint and signature before trusting
the checksums; run all of these commands before the `install` step above. The
[release verification guide](/guide/release-verification) explains the trust
chain, expected output, failure cases, and Cosign container verification.

::: warning Download SHA256SUMS into the same directory as the archive
`sha256sum` looks for the archives in the current working directory, under the
names listed inside `SHA256SUMS`. If the two files sit in different
directories, it verifies nothing at all and reports
`SHA256SUMS: no file was verified`. That is not a pass: check for a line
ending in `OK` before installing.
:::

Run these commands from the directory holding the archive. Replace `1.4.0`
with the release you selected:

```sh
VERSION=1.4.0
wget "https://github.com/AngieGuardian/angie-guardian/releases/download/${VERSION}/SHA256SUMS"
wget "https://github.com/AngieGuardian/angie-guardian/releases/download/${VERSION}/SHA256SUMS.asc"
wget "https://github.com/AngieGuardian/angie-guardian/releases/download/${VERSION}/RELEASE-KEY.asc"

# The attached key is trusted only after this exact fingerprint matches.
gpg --show-keys --with-colons RELEASE-KEY.asc \
  | awk -F: '$1 == "fpr" { print $10; exit }'
# E0C7C029005B0CE6A7438BD571D11FF23454B9D7

gpg --import RELEASE-KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

```
angie-guardian-1.4.0-linux-amd64.tar.gz: OK
```

The signature must report a good signature from fingerprint
`E0C7 C029 005B 0CE6 A743 8BD5 71D1 1FF2 3454 B9D7`. The human-readable name or
email on a key is not sufficient. `SHA256SUMS` lists both architectures and the
Cosign public key, so `--ignore-missing` lets you verify only the files you
downloaded. Without it, absent files are reported as `FAILED open or read`.

A file that does not match reports `FAILED` instead of `OK` and exits non-zero;
do not install it. The GitLab and
[GitHub](https://github.com/AngieGuardian/angie-guardian/releases) releases
publish the same archives, checksums, signature and keys.

### Build from source (optional)

Source builds are for contributors or operators who intentionally need a
custom build. They require a repository checkout and the Go toolchain selected
by `go.mod` (currently Go 1.27.0):

```sh
git clone https://github.com/AngieGuardian/angie-guardian.git
cd angie-guardian
go build -o guardiand ./cmd/guardiand
```

After building, continue from the `install` command above. All remaining
commands use `/usr/local/bin/guardiand`, so the installation path is identical.

## 2. Configure Guardian

The release archive already contains the
[canonical `guardian.example.yaml`](https://github.com/AngieGuardian/angie-guardian/blob/main/guardian.example.yaml).
It is the recommended, thoroughly annotated host/systemd profile; the same
file is rendered as the [full annotated example](/examples#the-full-annotated-example).
Install it together with the starter WAF rules it actively references:

```sh
# Immutable policy: root-owned, readable but not writable by guardiand.
sudo install -d -o root -g guardian -m710 /etc/guardian
sudo install -d -o root -g guardian -m750 /etc/guardian/rules.d
sudo install -o root -g guardian -m640 guardian.example.yaml \
  /etc/guardian/guardian.yaml
sudo install -o root -g guardian -m640 deploy/rules-common.yaml \
  /etc/guardian/rules.d/common.yaml
```

If you use Argon2id, install its browser assets separately as well. The
release archive contains them under `assets/`; the source tree keeps them in
`web/vendor/guardian-argon2/`. Angie serves these files directly, so they must
be present before reloading the vhost:

```sh
sudo install -d -m755 /usr/share/guardian/assets
sudo install -m644 assets/argon2id-worker-db57362e2dddfb66.js \
  assets/argon2id-runtime-1b3aa08f6d118ad6.js \
  assets/argon2id-4507b469b9b103a5.wasm /usr/share/guardian/assets/
```

For a source checkout, use `web/vendor/guardian-argon2/` in place of
`assets/`. The shipped Angie snippet's `/__guardian/assets/` location points
to `/usr/share/guardian/assets/` by default.

Every later command uses `/etc/guardian/guardian.yaml`. The rules file is
equally required: the example enables it with fail-fast loading, so validation
correctly fails if it was not installed.

Before starting Guardian, edit `/etc/guardian/guardian.yaml` as root and:

- replace or remove the exact `example.com`, `api.example.com`, and
  `static.example.com` domain entries so they match real Angie vhosts;
- review the defaults and starter WAF rules against the site's legitimate
  paths and clients;
- choose the appropriate [store backend](/guide/production#choosing-a-store-backend);
- keep the listeners on loopback for a same-host Angie deployment; and
- reject unknown hosts in Angie's `default_server`, because unknown hostnames
  inherit Guardian's `defaults` rather than a named domain profile.

```sh
sudoedit /etc/guardian/guardian.yaml
```

The signing key, retired keys, admin token, and Pebble store paths in this
profile deliberately point to `/var/lib/guardian`. The systemd unit creates
that service-owned state directory; policy under `/etc/guardian` remains
read-only. See [Filesystem layout and ownership](/guide/production#filesystem-layout-and-ownership)
for the security model.

Validate the YAML and every referenced local artifact, including the rules
file, before installing the service:

```sh
sudo -u guardian /usr/local/bin/guardiand -t
```

`-t` reads `/etc/guardian/guardian.yaml` unless you pass `-config`, which is
the file you just edited. A valid config prints
`config /etc/guardian/guardian.yaml: ok` and exits `0`.

Continue with the [configuration guide](/guide/configuration), the
[configuration reference](/reference/configuration), and the
[WAF rules walkthrough](/guide/configuration#waf-rules)
when adapting the annotated profile.

### Minimal evaluation config (alternative)

The full annotated profile above is the recommended host starting point. If
you only want a disposable foreground evaluation, create a separate config
such as `/tmp/guardian-evaluation/guardian.yaml` instead. This example uses an
in-memory store, no admin listener, and no WAF rules; do not feed it into
the production systemd steps below:

```sh
install -d -m700 /tmp/guardian-evaluation
cat >/tmp/guardian-evaluation/guardian.yaml <<'YAML'
listen: 127.0.0.1:8071
signing_key_file: /tmp/guardian-evaluation/ed25519.key
store: { backend: memory }
defaults:
  pow: { enabled: true, base_difficulty: 5 }
domains:
  localhost: {}
YAML
guardiand -config /tmp/guardian-evaluation/guardian.yaml -t
```

Run it in one terminal with
`guardiand -config /tmp/guardian-evaluation/guardian.yaml`. Use a second
terminal for health checks, then stop the foreground daemon with Ctrl-C and
remove `/tmp/guardian-evaluation`. The rest of this guide assumes the
recommended annotated profile instead.

## 3. Install and wire the Angie configuration

Install the three required Guardian integration snippets,
[`deploy/angie-guardian-limits.conf`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-guardian-limits.conf),
[`deploy/angie-guardian.conf`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-guardian.conf)
and
[`deploy/angie-guardian-location.conf`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-guardian-location.conf),
at the paths used by the examples:

```sh
sudo install -Dm644 deploy/angie-guardian-limits.conf \
  /etc/angie/angie-guardian-limits.conf
sudo install -Dm644 deploy/angie-guardian.conf \
  /etc/angie/angie-guardian.conf
sudo install -Dm644 deploy/angie-guardian-location.conf \
  /etc/angie/angie-guardian-location.conf
```

The release also contains `angie-hardening-http.conf` and
`angie-hardening-server.conf`. They are an optional Angie server-hardening
profile and are installed automatically by `scripts/install.sh`.
Review body, streaming, timeout, and concurrency requirements before enabling
them; see [Angie Server Hardening](/guide/angie-hardening).

For the normal fail-open installation, do not edit any of the three files.
`angie-guardian.conf` contains reusable internal Guardian endpoints and no
site backend. `angie-guardian-location.conf` contains handler-neutral
authorization directives that normally go beside it at `server {}` scope and
are inherited by the vhost's content locations. The [Angie guide's fail-mode
section](/guide/angie#fail-open-without-duplicating-the-site-handler) documents
the deliberate edit for a fail-closed deployment.

Does the vhost set site-wide security headers with `add_header`
(Content-Security-Policy, Strict-Transport-Security)? The snippet already
keeps the site's CSP off Guardian's challenge and denied pages (the pages
carry their own strict CSP), so the vhost policy needs no change; but that
also stops other server-wide `add_header` directives from applying to those
two pages, so re-add HSTS there if you rely on it. Details in
[Site security headers and the challenge page](/guide/angie#site-security-headers-and-the-challenge-page).

Add the baseline include and keepalive upstream once inside Angie's `http {}` context (either in
`/etc/angie/angie.conf` or a file it includes there):

```nginx
include angie-guardian-limits.conf;

upstream guardian {
    # TCP works for every Angie worker user.
    server 127.0.0.1:8071;
    # Host-local alternative: replace the line above if you prefer the socket:
    # server unix:/run/guardian/guardian.sock max_conns=512;
    keepalive 64;
}
```

The default socket mode is `0660`. For group-restricted access, add the user
named by Angie's top-level `user` directive to `guardian` and restart Angie so
new workers receive the supplementary group:

```sh
sudo usermod --append --groups guardian <angie-worker-user>
```

If you prefer not to change that account, set the following in
`/etc/guardian/guardian.yaml`, validate with `guardiand -t`, and restart
Guardian:

```yaml
socket_mode: "0666"
```

This makes the socket available to every local process, which can then forge
the `X-Guardian-*` client identity headers Guardian trusts from Angie. Use TCP
or the default group-restricted mode on hosts where local users are not all
trusted.

Then include the two server snippets once inside each protected `server {}` block. Every
content location in that vhost inherits Guardian. Leave all existing static,
FastCGI, or reverse-proxy locations unchanged:

```nginx
include angie-guardian.conf;
include angie-guardian-location.conf;
```

Both names resolve against Angie's prefix, `/etc/angie` on the official
packages and images: see [Wire it into Angie](/guide/angie).

The [full Angie guide](/guide/angie) and
[server-hardening guide](/guide/angie-hardening) explain real client-IP restoration,
fail-open versus fail-closed operation, request and connection limits, logging,
request-body limitations, and a complete static + `try_files` + PHP-FPM
example (including the static-only `$uri $uri/ =404` form), server-level
snippet includes that add sibling asset locations, and the one
`auth_request off` needed in an internal PHP front-controller target.

Do not reload Angie yet: Guardian should be healthy first. Validate the edited
configuration now so syntax or duplicate-location errors are caught safely:

```sh
sudo angie -t
```

## 4. Start and verify

Install the shipped systemd unit, start Guardian, and inspect its readiness:

```sh
sudo install -Dm644 deploy/guardiand.service \
  /etc/systemd/system/guardiand.service
sudo systemctl daemon-reload
sudo systemctl enable --now guardiand
sudo systemctl --no-pager --full status guardiand
sudo journalctl -u guardiand -n 50 --no-pager
```

The unit repeats config validation in `ExecStartPre`, creates
`/var/lib/guardian` as `guardian:guardian` with mode `0700`, and creates the
socket parent `/run/guardian` with mode `0755`. All configured listeners
expose their own health endpoint:

```sh
curl --fail http://127.0.0.1:8071/healthz   # auth listener (liveness)
sudo -u guardian curl --fail --unix-socket /run/guardian/guardian.sock \
  http://localhost/healthz                  # Unix auth listener (liveness)
curl --fail http://127.0.0.1:8072/healthz   # admin listener (liveness)
curl --fail http://127.0.0.1:8072/readyz    # is the store actually working?
```

Now apply the Angie configuration that already passed `angie -t`. A normal
reload is enough unless you added its worker user to the `guardian` group:

```sh
sudo systemctl reload angie
# sudo systemctl restart angie # if its worker group membership changed
```

Request the real protected URL through Angie. A raw `curl` has no Guardian
cookie, so it should receive the challenge page rather than silently reaching
the site's original static, FastCGI, or proxy handler:

```sh
curl -i https://example.com/
```

Replace `example.com` with the hostname you configured. Finally, open that URL
in a browser: the first visit should solve proof of work, while a subsequent
visit should reuse the signed cookie and pass without another challenge.

For backups, monitoring, store durability, secret ownership, resource tuning,
containers, multi-instance deployments, and future upgrades, continue with
[Run it in Production](/guide/production).

`guardiand` is the runtime service and is all the basic installation needs.
If you later enable anomaly scoring, use the optional offline `guardian-train`
companion as described in [Train the Anomaly Model](/guide/anomaly), then follow
the [production timer setup](/guide/production#running-the-anomaly-trainer).
