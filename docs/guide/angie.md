# Wire it into Angie

Guardian hooks into Angie with stock `auth_request` directives: no custom
build, no C module. Angie makes a fast internal subrequest to the sidecar for
every request to a protected `server {}` block.

## The two snippets

Add the keepalive upstream once in the `http {}` context. Then copy/adapt the
per-server snippet for each protected vhost: replace both
`proxy_pass http://your_backend` placeholders. The shipped file already
declares `location /`; if your vhost has one, merge its Guardian directives
into that location instead of creating a duplicate.

```nginx
# http {} context, REQUIRED for throughput (connection reuse to the sidecar):
upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}

# each protected server {} block, after adapting backend placeholders:
include /etc/angie/angie-guardian.conf;   # from deploy/angie-guardian.conf
```

`deploy/angie-guardian.conf` documents the fail-open toggle (what happens when
the sidecar is down) and the challenge/pass/denied routes.

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
If the sidecar is unreachable, traffic passes through unprotected rather than
taking your site down. The toggle is documented in the snippet itself.
:::

## JSON access logs (for the anomaly trainer)

To feed the anomaly trainer, switch protected vhosts to the JSON access log
format from `deploy/angie-json-log.conf`:

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
