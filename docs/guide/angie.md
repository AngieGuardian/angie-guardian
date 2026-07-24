# Wire it into Angie

Guardian hooks into Angie with stock `auth_request` directives: no custom
build, no C module. Angie makes a fast internal subrequest to the sidecar for
every request handled by a protected location.

## One daemon, many virtual hosts

Guardian is already multi-domain. Angie sends `$host` as `X-Guardian-Host`,
and the daemon selects the matching `domains:` policy in `guardian.yaml`
(case-insensitive, with a port or trailing dot ignored). Hosts without an
explicit entry use `defaults`. One `guardiand` listener and one Angie
`upstream guardian` can therefore protect many `server {}` blocks; you do not
need one daemon or one edited Guardian snippet per domain.

The Angie integration has three deliberately separate pieces:

1. Define the keepalive `upstream guardian` once in `http {}`.
2. Include `angie-guardian.conf` unchanged in each protected `server {}`. It
   owns only Guardian's internal auth/challenge/denied endpoints.
3. Include `angie-guardian-location.conf` beside it at `server {}` scope. Its
   handler-neutral directives are inherited by all of that vhost's locations.

This separation makes the same server glue work for a reverse proxy, static
files, FastCGI, `try_files`, or a mixture of them.

The two per-vhost files are separate for **scope**, not because the protection
directives require a `location` block. `angie-guardian.conf` always belongs at
`server {}` scope because it declares Guardian's internal and named locations.
`angie-guardian-location.conf` only activates the authorization check, and its
directives are valid at either `server` or `location` scope:

- Include both files at `server {}` scope to protect the whole vhost. This is
  the normal and safest setup: exact paths, asset regexes, and other sibling
  locations inherit Guardian automatically.
- For deliberately selective protection, include `angie-guardian.conf` at
  server scope, but include `angie-guardian-location.conf` only inside the
  public locations Guardian should check. Other locations then incur no
  Guardian subrequest at all.

If these were merged, including the server endpoints would necessarily enable
Guardian for the entire vhost; selective deployments would have to disable it
again in every other location. Keeping activation separate supports both
models without duplicating the challenge/fail-open plumbing.

```nginx
# http {} context, REQUIRED for throughput (connection reuse to the sidecar):
upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}

# Only for this reverse-proxy example; static/FastCGI sites do not need it.
upstream my_application {
    server 127.0.0.1:8080;
}

# each protected server {} block:
include /etc/angie/angie-guardian.conf;
include /etc/angie/angie-guardian-location.conf;

location / {
    proxy_pass http://my_application;
}
```

[`deploy/angie-guardian.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian.conf) documents the fail-open toggle (what happens when
the sidecar is down) and the challenge/pass/denied routes. The companion
[`deploy/angie-guardian-location.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-guardian-location.conf)
contains only directives valid in `server` or `location` context.

## Static files and a PHP front controller

Do not invent a proxy upstream for a site that Angie already serves with
`root`, `try_files`, and FastCGI. Add the reusable Guardian includes at server
scope and leave the site's content directives alone:

For a static-only site, that is simply:

```nginx
server {
    server_name static.example.com;
    root /var/www/static.example.com;

    include /etc/angie/angie-guardian.conf;
    include /etc/angie/angie-guardian-location.conf;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

An existing file or directory is served only after Guardian allows the
request; a missing path remains the site's normal `404`. If your vhost defines
additional public `location` blocks, directly or through another included
file, they are siblings of `location /`, not children of it. Because the
protection include is at server scope, those locations inherit Guardian
automatically; there is no need to repeat the include in every asset location.
An `allow all` in an exact `robots.txt` location affects Angie's address-access
module; it does not cancel the separately inherited `auth_request`. Likewise,
`expires`, `add_header`, and `access_log off` in asset locations do not disable
Guardian. A hidden-file location that immediately `return 404`s remains an
intentional early rejection rather than a protection bypass.

The PHP front-controller form follows the same rule:

```nginx
server {
    server_name example.com;
    root /var/www/example/public;

    # Reused unchanged in every protected vhost.
    include /etc/angie/angie-guardian.conf;
    include /etc/angie/angie-guardian-location.conf;

    location / {
        # Existing site behavior stays exactly as it was.
        try_files $uri /index.php$is_args$args;
    }

    location ~ ^/index\.php(/|$) {
        default_type application/x-httpd-php;
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock; # use your real PHP-FPM target

        # Only try_files may enter this location. The original request was
        # already authorized in location /, so do not authorize it again.
        auth_request off;
        internal;
    }
}
```

`try_files` serves an existing static file only after the access phase, so the
file is protected. Its fallback is an internal redirect to the FastCGI
location. `auth_request off` in that `internal` location avoids doing two auth
subrequests for one request and is safe because an external request cannot
enter it. If your PHP location is publicly reachable instead, do **not** turn
authorization off there.

Angie selects only one content location. Independent sibling locations such
as `/api/`, `/assets/`, or a WebSocket endpoint do not pass through
`location /` when a more specific location wins. This is why server-scope
inheritance is the default:

```nginx
server {
    include /etc/angie/angie-guardian.conf;
    include /etc/angie/angie-guardian-location.conf;

    location ^~ /.well-known/acme-challenge/ {
        auth_request off;                 # deliberate public exception
        root /var/www/acme;
    }

    location /assets/ { root /srv/site; }
    location /api/    { proxy_pass http://api; }
}
```

Use `auth_request off` only for deliberate exceptions: public health/ACME
endpoints you truly want unprotected, or a non-public internal target reached
only after an already-authorized location. If you want Guardian on only part
of a vhost, omit the server-scope protection include and place it directly in
each selected public location instead.

Inheritance can be overridden by a child location. Audit any location that
already declares `auth_request`/`auth_request off`; it will not inherit the
server-level Guardian check. Also note that Angie inherits `error_page`
directives only when the child declares none of its own. A child with a custom
`error_page` remains denied when Guardian returns 401/403, but it will lose the
styled challenge/denied diversion unless you place the protection include at
that location level alongside its error-page rules.

## Fail-open without duplicating the site handler

Fail-open remains the shipped default. The internal `/__guardian/auth`
location intercepts only a Guardian connection failure, timeout, or 5xx and
turns it into `204`. `auth_request` treats that as allow and resumes the
original location, whether it uses static files, `try_files`, FastCGI, or
`proxy_pass`.

This is intentionally not a generic `@guardian_bypass` content location: such
a location would have to repeat the site's `proxy_pass` or FastCGI/static
logic, would drift from the real handler, and could not be shared by different
domains. Errors returned later by the application or PHP-FPM are not
intercepted by Guardian's fail-open rule. To fail closed, comment out the 5xx
`error_page` line inside `/__guardian/auth`; the now-unused
`@guardian_fail_open` location may then also be commented out. Removing only
the named location while it is still referenced is an invalid Angie config.

Fail-open preserves availability, not protection. Keep Angie's `limit_req`
and `limit_conn` in front of Guardian; they still apply while the daemon is
down and bound what reaches the original handler.

## Preserve the real client IP behind a proxy or CDN

The shipped snippet deliberately sends Angie's `$remote_addr` to Guardian.
If Angie itself sits behind a load balancer, CDN, ingress, or another reverse
proxy, configure Angie's real-IP module first so `$remote_addr` is restored to
the actual client address. Otherwise every visitor appears to be the proxy:
one attacker can score a behavioural block or rate limit that affects everyone.

```nginx
# http {} context: use only the exact networks owned by your proxy/CDN.
set_real_ip_from 10.20.0.0/16;
set_real_ip_from 2001:db8:1234::/48;
real_ip_header X-Forwarded-For;       # or your provider's authenticated header
real_ip_recursive on;
```

For PROXY protocol deployments, configure the listener and use
`real_ip_header proxy_protocol` instead. Never trust `X-Forwarded-For` from
arbitrary internet clients: an over-broad `set_real_ip_from` lets attackers
choose the identity Guardian blocks, rate-limits, and binds tokens to. Verify
the result in access logs before enabling behavioural blocking or nftables
offload.

::: info Fail-open by default
If the sidecar is unreachable, Angie resumes the vhost's original content
handler unprotected rather than taking your site down. The toggle is documented
in the server snippet itself.
:::

## JSON access logs (for the anomaly trainer)

To feed the anomaly trainer, switch protected vhosts to the JSON access log
format from [`deploy/angie-json-log.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-json-log.conf):

```nginx
access_log /var/log/angie/example.com.access.json guardian_json;
```

See [Train the Anomaly Model](/guide/anomaly) for what to do with the logs.

## Rate limiting (volumetric DDoS)

PoW taxes bots that speak HTTP and solve the puzzle; it does **not** absorb a
raw flood. Every request still costs an `auth_request` subrequest. A client that
follows the challenge redirect also makes the sidecar issue a challenge (and
persist it, unless [attack mode](/guide/attack-mode)'s stateless issuance has
kicked in). Under enough load the sidecar saturates and fail-open (the default)
sends the flood straight to your backend; attack mode's optional
`max_inflight` load-shedding bound turns that into fast `503`s for unvouched
clients instead.

Blocked clients no longer add to that cost inside the sidecar: an always-on
in-process mirror answers the block lookup with no store read, and the
optional [kernel offload](/guide/block-offload) can drop a blocked client's
packets in nftables before Angie ever runs the subrequest. That keeps a flood
from *already-known-bad* IPs cheap, but it does not help against a first-time
flood from fresh IPs, which is what the rate limits below are for.

Volumetric DDoS is Angie's job, in front of the `auth_request`, so a flood is
dropped before it reaches the sidecar at all. The two layers are
complementary: rate limits absorb volume, PoW taxes the bots that get through.
Tune the rates to your real traffic before enabling.

```nginx
# http {} context: one shared zone per limiter.
limit_req_zone  $binary_remote_addr zone=guard:10m rate=30r/s;
limit_conn_zone $binary_remote_addr zone=gconn:10m;

# in each protected server {} (or the location / block). limit_req runs in an
# earlier phase than auth_request, so a rejected flood never reaches the sidecar.
limit_req  zone=guard burst=60 nodelay;   # smooth spikes, reject sustained floods
limit_conn gconn 20;                       # cap concurrent connections per client
limit_req_status  429;
limit_conn_status 429;
```

## Site security headers and the challenge page

Many vhosts set site-wide security headers with `add_header`: a
Content-Security-Policy, Strict-Transport-Security, X-Frame-Options and so
on. In Angie (as in nginx), `add_header` directives are inherited from
`server {}` scope into a location only when that location defines no
`add_header` of its own. Without countermeasures, those site headers would
therefore also be attached to the responses Angie proxies from Guardian,
including the challenge interstitial.

For most headers that is harmless. For a site CSP it is not: browsers enforce
every `Content-Security-Policy` header on a response, and the interstitial
needs things a good site policy has no reason to allow, namely an inline
script and style, a `blob:` Web Worker running the PoW solver, and a
same-origin `fetch` that submits the solution. Under a typical site policy
(no `worker-src`, so the worker falls back to a `script-src` without
`blob:`), the solver is blocked: the page renders but reports "Solver error"
(or, depending on the browser, sits at "Starting…" forever), and the browser
console shows a violation like

```
Content-Security-Policy: The page's settings blocked a worker script
(worker-src) at blob:https://example.com/... from being executed because it
violates the following directive: "script-src 'unsafe-inline' 'self'"
```

The shipped `deploy/angie-guardian.conf` therefore gives `@guardian_challenge`
and `@guardian_denied` their own `add_header Content-Security-Policy`, fitted
to exactly what each page uses and nothing more. That one directive does two
jobs: Guardian's pages carry a strict policy of their own, and, by the
inheritance rule above, the vhost's server-level `add_header` set (site CSP
included) stops applying to them. Loosening the site-wide CSP instead, by
adding `worker-src blob:` to it, would weaken the whole site to fix one
internal page; don't do that.

The flip side of that cancellation is that it covers **all** inherited
`add_header` directives, not just the CSP. If the vhost sets other
server-wide headers on every response, re-add them explicitly inside both
locations; this is one of the deliberate snippet edits, like the fail-mode
choice. `Strict-Transport-Security` is the case worth caring about: for a
fresh visitor the interstitial is typically the *first* response the browser
receives, so if you rely on HSTS, mirror the vhost's exact value there:

```nginx
location @guardian_challenge {
    # ... shipped directives, including the page CSP ...
    add_header Strict-Transport-Security "max-age=63072000" always;  # match your vhost
}
```

Headers your backend application sets on its own responses are unrelated to
any of this: Guardian's pages never pass through the backend, and
`auth_request` responses never reach the client.

## Request types and edge cases

Guardian's auth subrequest carries only the request line and headers, never the
body (`proxy_pass_request_body off`). That keeps the auth hop cheap and means
these common request shapes work as you'd expect, each covered by the
end-to-end suite:

- **Any method (POST, PUT, DELETE…).** The WAF evaluates method, path, query,
  User-Agent and targeted headers on every request, body or not. A `block`/`deny`
  rule fires on a POST just as on a GET. Request bodies are never inspected; see
  the [security model](/guide/threat-model#what-guardian-does-not-defend-against);
  that's the backend's or a full inline WAF's job. In `pow.mode: always`, an
  unvouched non-idempotent request is diverted before its body reaches the
  backend. Angie fetches the interstitial internally with GET and Guardian
  never stores or replays the body; after solving, the browser/client must
  retry or confirm resubmission. For machine APIs where that interaction is
  unsuitable, disable PoW or use `mode: suspicion` with an appropriate policy.
- **Large uploads.** The real body streams to your backend unbuffered and
  intact; the body-less auth hop doesn't touch it. But `auth_request` does **not**
  change Angie's own `client_max_body_size` (default 1 MiB): a body over that
  limit is rejected by Angie with `413` before Guardian or the backend see it.
  If you accept large uploads, raise `client_max_body_size` in Angie as you
  normally would; it's independent of Guardian.
- **WebSocket / SSE / long-lived streams.** The upgrade or initial request goes
  through `auth_request` once, like any request; once allowed, the connection
  proxies to your backend and Guardian is no longer in the path (it never sees
  the streamed frames). Ensure your `location` forwards the upgrade headers
  (`proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection
  "upgrade";`) for the backend proxy, exactly as you would without Guardian.
- **HTTP/2 and HTTP/3.** Guardian is oblivious to the client protocol version:
  it acts on the decoded request Angie hands the subrequest, so an HTTP/2 or
  HTTP/3 client is handled identically to HTTP/1.1. The sidecar hop itself uses
  keepalive'd HTTP/1.1 to loopback, which is an internal detail. The token
  cookie and challenge flow work the same across versions.
