# Getting Started

Install Guardian on a Debian/Ubuntu host, connect it to an existing Angie site,
and verify the first protected request.

## Prerequisites

- Angie already serving the site you want to protect.
- A Debian or Ubuntu systemd host with `amd64` (`x86_64`) or `arm64` (`aarch64`) architecture.
- Root or `sudo` access, plus `curl`.

For a pinned release, another Linux distribution, or a source build, follow
[Manual Installation](/guide/manual-installation). For containers, follow the
[production Docker guide](/guide/production#docker).

## 1. Install Guardian

```sh
curl -fsSL https://raw.githubusercontent.com/AngieGuardian/angie-guardian/main/scripts/install.sh | sudo bash
```

The installer verifies the latest release and starts `guardiand`. The main
directories for everyday operations are:

- `/etc/guardian/`: `guardian.yaml` and starter rules in `rules.d/`.
- `/etc/angie/`: integration and optional hardening snippets.
- `/var/lib/guardian/`: generated keys, tokens, and store data.

Repeat runs preserve local configuration and state; review any **ACTION REQUIRED** notices.

It does not edit your Angie configuration or reload Angie. Complete the steps
below before protecting a site.

## 2. Configure Guardian

Edit the installed [annotated profile](/examples#the-full-annotated-example):

```sh
sudoedit /etc/guardian/guardian.yaml
```

- Replace or remove the `example.com`, `api.example.com`, and `static.example.com`
  domain entries so they match your real Angie vhosts.
- Review the defaults and starter WAF rules against your site's legitimate
  paths and clients.
- Keep the listeners on loopback for this same-host installation.
- Reject unknown hosts in Angie's `default_server`; otherwise they inherit
  Guardian's `defaults`.

Validate the edited configuration, then restart Guardian to apply it:

```sh
sudo -u guardian /usr/local/bin/guardiand -t
sudo systemctl restart guardiand
```

A valid config prints `config /etc/guardian/guardian.yaml: ok` and exits `0`.
See [Configuration](/guide/configuration) for policy options and
[PoW algorithms](/guide/pow-algorithms) for optional Argon2id configuration.

## 3. Install and wire the Angie configuration

The installer already placed the snippets in `/etc/angie`. Add these includes
and the upstream **once inside your existing `http {}` block**, either in
`/etc/angie/angie.conf` or a file it includes there:

```nginx
include angie-guardian-limits.conf;
include angie-json-log.conf;

upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}
```

Add these includes **inside each protected `server {}` block**:

```nginx
include angie-guardian.conf;
include angie-guardian-location.conf;
```

The shipped snippets use fail-open operation. Existing static, FastCGI, and
reverse-proxy locations inherit the authorization directives.

If a location defines its own `error_page`, it replaces **all** inherited
error-page mappings, including Guardian's challenge and denial mappings.
Repeat the protection include in that location, before any site-specific
`401` or `403` mapping:

```nginx
location / {
    include angie-guardian-location.conf;
    error_page 404 /404.html;
    try_files $uri $uri/ =404;
}
```

Keep both server-level includes as well. See
[Locations with their own error pages](/guide/angie#a-location-with-its-own-error-page-loses-the-styled-diversion).

If Angie is behind a proxy or CDN, configure
[real client-IP restoration](/guide/angie#preserve-the-real-client-ip-behind-a-proxy-or-cdn)
before enabling protection. For PHP front controllers, custom error pages,
or Unix sockets, see [Wire it into Angie](/guide/angie).

### Optional hardening and logging

The installer also provides `angie-hardening-http.conf` and
`angie-hardening-server.conf`. These bound connection/request work with
timeouts, request-size limits, and concurrency limits. Review your site's
upload and streaming requirements before enabling them; see
[Angie Server Hardening](/guide/angie-hardening#enable-the-profile).

The JSON include above declares `guardian_json`; it does not change your log
destination. To enable JSON logging, add this inside the protected `server {}`
block, using your site's filename:

```nginx
access_log /var/log/angie/example.com.access.json guardian_json;
```

See [JSON access logs](/guide/angie#json-access-logs-for-the-anomaly-trainer).
If you use Fail2Ban, also follow
[Keep Guardian decisions out of a Fail2Ban input log](/guide/angie#keep-guardian-decisions-out-of-a-fail2ban-input-log).

## 4. Verify and enable protection

Check that Guardian is running and its store is ready:

```sh
sudo systemctl --no-pager --full status guardiand
curl --fail http://127.0.0.1:8071/healthz
curl --fail http://127.0.0.1:8072/readyz
```

If a check fails, inspect `sudo journalctl -u guardiand -n 50 --no-pager`
before continuing. Once Guardian is healthy, validate Angie and reload it
only if validation succeeds:

```sh
sudo angie -t && sudo systemctl reload angie
```

Request your real protected hostname through Angie:

```sh
curl -i https://example.com/
```

With the default PoW policy, a client without a Guardian cookie should receive
the challenge page. Open the same URL in a browser: the first visit should
solve proof of work, and subsequent visits should reuse the signed cookie.

For everyday operator commands, run `sudo guardianctl --help` or see
[Admin operations](/guide/admin#everyday-operations). Continue with
[Run it in Production](/guide/production) for backups, monitoring, store
choices, upgrades, and optional anomaly training.
