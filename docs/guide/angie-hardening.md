# Angie Server Hardening

Guardian makes an authorization decision only after Angie has accepted a
connection and decoded an HTTP request. TLS handshakes, incomplete headers,
request bodies, HTTP/2 streams, client response reads, and keepalive sockets are
therefore Angie's work. This guide describes the optional server-hardening
profile for that work.

The profile is not a volumetric DDoS service. It places local, deterministic
bounds around client work that reaches Angie. Keep provider, CDN, load-balancer,
firewall, SYN-flood, and bandwidth protection upstream.

## Enable the profile

The release archive and installer provide two separate files:

- `angie-hardening-http.conf` defines shared zones and the bounded TLS session
  cache. Include it once in `http {}`.
- `angie-hardening-server.conf` applies timeouts, request-size limits, HTTP/2
  limits, and active-request admission. Include it in each public `server {}`
  you want to protect.

Keep the two configuration scopes separate. The main Angie configuration owns
process-wide settings, shared HTTP state, and upstream groups. For example,
`/etc/angie/angie.conf` can contain:

```nginx
worker_processes auto;
worker_rlimit_nofile 8192;

events {
    worker_connections 4096;
}

http {
    include /etc/angie/mime.types;
    default_type application/octet-stream;

    include /etc/angie/angie-guardian-limits.conf;
    include /etc/angie/angie-hardening-http.conf;

    upstream guardian {
        # TCP works for every Angie worker user.
        server 127.0.0.1:8071;
        # Host-local alternative: replace the line above with:
        # server unix:/run/guardian/guardian.sock max_conns=512;
        keepalive 64;
    }

    # Only needed for this reverse-proxy example.
    upstream my_application {
        server 127.0.0.1:8080;
    }

    include /etc/angie/http.d/*.conf;
}
```

Then keep the domain-specific configuration in its usual separate vhost file,
for example `/etc/angie/http.d/example.com.conf`:

```nginx
server {
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name example.com;

    ssl_certificate     /etc/angie/tls/example.com.crt;
    ssl_certificate_key /etc/angie/tls/example.com.key;

    include /etc/angie/angie-hardening-server.conf;
    include /etc/angie/angie-guardian.conf;
    include /etc/angie/angie-guardian-location.conf;

    location / {
        proxy_pass http://my_application;
    }
}
```

For a static or FastCGI site, keep its existing content locations and omit the
example `upstream my_application`; the hardening and Guardian includes stay at
the same scopes.

For a container, pair the worker limits with a matching process limit. The
reference Compose files use:

```yaml
ulimits:
  nofile:
    soft: 8192
    hard: 8192
```

Always run `angie -t` before reloading. The snippets require Angie's HTTP SSL,
HTTP/2, and connection-limit modules; the reference image includes all three.

## Reference version and defaults

The reference target is Angie 1.12.1, pinned by the multi-platform image digest
in the Compose files. Later Angie releases may change server behavior; keep the
image pinned until the profile has been validated against the replacement
version.

| Boundary | Shipped value | What it bounds |
|---|---:|---|
| `client_header_timeout` | `10s` | Inactivity while TLS/request headers are incomplete |
| `client_body_timeout` | `15s` | Inactivity between request-body reads |
| `send_timeout` | `15s` | Inactivity between writes to a slow response reader |
| `keepalive_timeout` | `15s` | Idle HTTP/1.1 keepalive lifetime |
| `keepalive_requests` | `1000` | Requests reused on one keepalive connection |
| `keepalive_time` | `1h` | Total keepalive connection lifetime |
| `large_client_header_buffers` | `4 8k` | Large decoded request-header capacity |
| `client_max_body_size` | `1m` | Maximum accepted request body |
| `http2_max_concurrent_streams` | `64` | Concurrent streams advertised to an HTTP/2 peer |
| `http2_body_preread_size` | `16k` | Request-body data buffered before application processing |
| per-client `limit_conn` | `20` | Complete active requests from one source address |
| per-vhost `limit_conn` | `1024` | Complete active requests for one server name |
| TLS session cache | `10m`, `10m` expiry | Resumable TLS session state |
| `worker_connections` | `4096` | Connections handled by each worker |
| worker/container `nofile` | `8192` | File descriptors available to the Angie process |

Angie timeouts are inactivity intervals, not total upload/download deadlines.
A client that continuously makes progress can legitimately remain connected
longer. Conversely, `reset_timedout_connection on` closes timed-out sockets
without keeping their state around.

`limit_conn` begins counting only after complete request headers are available.
On HTTP/2 and HTTP/3, each complete request counts separately. It does not bound
silent TCP peers, partial TLS handshakes, or never-completed headers; the
timeouts, worker/socket ceilings, kernel queues, and upstream admission own
those earlier stages.

Angie inherits `limit_conn` directives only when the current configuration
level has none. Keep site-specific connection limits in the same `server {}` as
the hardening include. If an application location defines `limit_conn`, repeat
both hardening limits in that location too. See the
[application limit example](/guide/angie#front-door-admission-and-application-rate-limits).

## Tune before enabling

The shipped values fit conventional pages and APIs. Copy or override the
profile for workloads with different semantics:

- Upload endpoints need a deliberate `client_max_body_size` and may need a
  longer `client_body_timeout`. Guardian still never inspects the body.
- WebSocket, SSE, streaming downloads, long polling, and large responses may
  need longer read/write/keepalive values. A blanket `15s` is not suitable for
  every stream.
- NAT gateways can place many legitimate users behind one address. Raise the
  per-client active-request budget or use a keyed zone that matches your trusted
  proxy and real-IP design.
- Size the per-vhost budget from downstream concurrency, not CPU count alone.
  One client request may consume a client socket, an auth subrequest, a Guardian
  upstream socket, and an origin upstream socket.
- Configure `set_real_ip_from` and `real_ip_header` correctly before relying on
  an address-keyed limit. Never trust a client-supplied forwarding header from
  the public internet.

Do not put a fixed request-per-second limit on `/__guardian/auth`: it runs once
for every protected application request and would silently become a universal
site budget. Keep application rate limits explicit and capacity-derived.

## HTTP/2 and Rapid Reset

The profile lowers the advertised concurrent-stream budget to 64 and limits
complete active requests independently of connection count. Its validation
covers the advertised SETTINGS value, decoded headers beyond the configured
buffers, and repeated resets of incomplete-body streams. The required outcomes
are:

- no reset upload reached the origin;
- Angie still serves a normal HTTP/2 request;
- file-descriptor use returns to a bounded level after stalled TLS clients.

These bounds do not provide unlimited attack capacity. Rapid Reset mitigations
also depend on the exact Angie build and on admission before traffic reaches
it. Keep the Angie image patched and pinned, then repeat the soak after an
upgrade.

## HTTP/3 boundary

Angie 1.12.1 in the pinned image contains the HTTP/3 module. The reference
topology does not publish a UDP listener and therefore provides no runtime QUIC
coverage. HTTP/3 production work must separately validate UDP admission, QUIC
handshake/state limits, migration, 0-RTT policy, stream concurrency, and the
exact listener syntax on the deployed Angie build.

Once Angie has decoded a request, Guardian's authorization contract is protocol
neutral. That does not make the earlier QUIC transport layer Guardian's job.

## Fail-open remains narrow

Guardian's documented fail-open path converts only a genuine auth-sidecar
upstream error into an allow. Angie request admission happens independently:
an oversized request still gets `413` and never reaches the origin when
Guardian is unavailable, while a normal request continues to the origin. A
local overload rejection must never be routed through the Guardian fail-open
location.

## Validate and soak

Run the deterministic suite after changing the profile or Angie image:

```sh
make e2e
```

Run the opt-in repeated HTTP/2 reset soak on a quiet target host:

```sh
make e2e-angie-soak ANGIE_HARDENING_SOAK_DURATION=5m
```

The soak has no timing threshold, so noisy CI hardware cannot turn throughput
variance into a false failure. It checks origin isolation and recovery while
reporting completed rounds and Angie file-descriptor counts. For production
capacity, add your TLS terminator, real certificates, client distribution,
upstream proxy, and expected application traffic; monitor Angie connection,
SSL failure, limit-zone, and slab counters through its API.

## Layer ownership

| Layer | Primary owner | Guardian contribution |
|---|---|---|
| Bandwidth, SYN/UDP flood, connection admission | Provider, CDN/LB, kernel/firewall | None before HTTP |
| TLS and QUIC handshakes | Angie/OpenSSL plus upstream terminator | None |
| HTTP parsing, bodies, timeouts, H2/H3 streams | Angie hardening profile | None until a request is decoded |
| Auth/WAF decision and PoW economics | Guardian | Allow, challenge, deny, refuse, or deliberate shed |
| Application concurrency and body semantics | Angie vhost plus origin | Guardian auth remains bodyless |

This division is the benefit of the profile: overload at Angie's front door is
bounded where it is created, while Guardian remains focused on request policy
and keeps its genuine outage behavior explicit.
