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
[production Docker guide](/guide/production#docker). The repository's Compose
stack is a demo/developer harness that builds the current checkout; it is not
the host installation described here.

## 1. Install a prebuilt release

Choose a pinned version on the
[releases page](https://gitlab.melroy.org/melroy/angie-guardian/-/releases),
under **Assets > Packages**. Most Intel and AMD servers use `linux-amd64`; an
ARM server uses `linux-arm64` instead. For example, to download and extract
version `0.12.0` for amd64:

```sh
wget https://gitlab.melroy.org/api/v4/projects/210/packages/generic/angie-guardian/0.12.0/angie-guardian-0.12.0-linux-amd64.tar.gz
tar -xzf angie-guardian-0.12.0-linux-amd64.tar.gz
cd angie-guardian-0.12.0-linux-amd64
```

Substitute the version you selected, without the leading `v` the releases page
shows on the tag. On ARM64, also replace `amd64` with `arm64` in the URL,
archive name, and directory name.

The extracted directory contains `guardiand`, the `guardian-train` and
`guardian-loadtest` companion tools, the optional `guardian.wasm`, the
canonical `guardian.example.yaml`, and the complete `deploy/` directory. The
installation below uses the binary, systemd unit, Angie snippets, and starter
rules directly from that directory.

Install the daemon and create its dedicated service identity:

```sh
sudo install -Dm755 guardiand /usr/local/bin/guardiand
getent group guardian >/dev/null || sudo groupadd --system guardian
id guardian >/dev/null 2>&1 || sudo useradd --system --gid guardian \
  --home-dir /var/lib/guardian --shell /usr/sbin/nologin guardian
```

### Verify the download (optional)

Every release publishes a `SHA256SUMS` file next to the archives, listing the
SHA-256 digest of each one. Downloading it alongside the archive lets you
confirm the file arrived intact and matches what the release pipeline built.
If you want this check, run it right after downloading the archive, before the
`install` step above.

::: warning Download SHA256SUMS into the same directory as the archive
`sha256sum` looks for the archives in the current working directory, under the
names listed inside `SHA256SUMS`. If the two files sit in different
directories, it verifies nothing at all and reports
`SHA256SUMS: no file was verified`. That is not a pass: check for a line
ending in `OK` before installing.
:::

Run both commands from the directory holding the archive you downloaded above:

```sh
# Same directory as angie-guardian-0.12.0-linux-amd64.tar.gz
wget https://gitlab.melroy.org/api/v4/projects/210/packages/generic/angie-guardian/0.12.0/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

```
angie-guardian-0.12.0-linux-amd64.tar.gz: OK
```

`SHA256SUMS` lists both architectures, so `--ignore-missing` is what lets you
verify just the one you downloaded. Without it, `sha256sum` reports the archive
you did not download as `FAILED open or read` and exits non-zero, which looks
like a verification failure but is not one.

A file that does not match reports `FAILED` instead of `OK` (and the command
exits non-zero); do not install it. The same `SHA256SUMS` is attached to the
[GitHub release](https://github.com/AngieGuardian/angie-guardian/releases) and
verifies identically.

::: warning Checksums detect corruption, not tampering
A checksum only proves the archive matches the `SHA256SUMS` you downloaded. It
is not a signature: anyone able to replace the archive could replace the
checksum file with it. Releases are not yet signed, and the container images
are not yet attested, so treat this as an integrity check rather than proof of
origin. [Issue #7](https://gitlab.melroy.org/melroy/angie-guardian/-/issues/7)
tracks signing the checksums and the images. Do not substitute an unpinned
`latest` download for the explicit version above.
:::

### Build from source (optional)

Source builds are for contributors or operators who intentionally need a
custom build. They require a repository checkout and the Go toolchain selected
by `go.mod` (currently Go 1.26.5):

```sh
git clone https://gitlab.melroy.org/melroy/angie-guardian.git
cd angie-guardian
go build -o guardiand ./cmd/guardiand
```

After building, continue from the `install` command above. All remaining
commands use `/usr/local/bin/guardiand`, so the installation path is identical.

## 2. Configure Guardian

The release archive already contains the
[canonical `guardian.example.yaml`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/guardian.example.yaml).
It is the recommended, thoroughly annotated host/systemd profile; the same
file is rendered as the [full annotated example](/examples#the-full-annotated-example).
Install it together with the starter signature rules it actively references:

```sh
# Immutable policy: root-owned, readable but not writable by guardiand.
sudo install -d -o root -g guardian -m710 /etc/guardian
sudo install -d -o root -g guardian -m750 /etc/guardian/rules.d
sudo install -o root -g guardian -m640 guardian.example.yaml \
  /etc/guardian/guardian.yaml
sudo install -o root -g guardian -m640 deploy/rules-common.yaml \
  /etc/guardian/rules.d/common.yaml
```

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
[signature-rules walkthrough](/guide/configuration#signature-rules-waf-keywords)
when adapting the annotated profile.

### Minimal evaluation config (alternative)

The full annotated profile above is the recommended host starting point. If
you only want a disposable foreground evaluation, create a separate config
such as `/tmp/guardian-evaluation/guardian.yaml` instead. This example uses an
in-memory store, no admin listener, and no signature rules; do not feed it into
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

Install the two shipped Angie snippets,
[`deploy/angie-guardian.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian.conf)
and
[`deploy/angie-guardian-location.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian-location.conf),
at the paths used by the examples:

```sh
sudo install -Dm644 deploy/angie-guardian.conf \
  /etc/angie/angie-guardian.conf
sudo install -Dm644 deploy/angie-guardian-location.conf \
  /etc/angie/angie-guardian-location.conf
```

For the normal fail-open installation, do not edit either file.
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

Add the keepalive upstream once inside Angie's `http {}` context (either in
`/etc/angie/angie.conf` or a file it includes there):

```nginx
upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}
```

Then include both snippets once inside each protected `server {}` block. Every
content location in that vhost inherits Guardian. Leave all existing static,
FastCGI, or reverse-proxy locations unchanged:

```nginx
include /etc/angie/angie-guardian.conf;
include /etc/angie/angie-guardian-location.conf;
```

The [full Angie guide](/guide/angie) explains real client-IP restoration,
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

The unit repeats config validation in `ExecStartPre` and creates
`/var/lib/guardian` as `guardian:guardian` with mode `0700`. Both configured
listeners expose their own health endpoint:

```sh
curl --fail http://127.0.0.1:8071/healthz   # auth listener (liveness)
curl --fail http://127.0.0.1:8072/healthz   # admin listener (liveness)
curl --fail http://127.0.0.1:8072/readyz    # is the store actually working?
```

Now apply the Angie configuration that already passed `angie -t`:

```sh
sudo systemctl reload angie
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
