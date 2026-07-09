# Wire it into Angie

Guardian hooks into Angie with stock `auth_request` directives: no custom
build, no C module. Angie makes a fast internal subrequest to the sidecar for
every request to a protected `server {}` block.

## The two snippets

Add the keepalive upstream once in the `http {}` context, then include the
per-server snippet in each protected `server {}` block:

```nginx
# http {} context, REQUIRED for throughput (connection reuse to the sidecar):
upstream guardian {
    server 127.0.0.1:8071;
    keepalive 64;
}

# each protected server {} block:
include /etc/angie/angie-guardian.conf;   # from deploy/angie-guardian.conf
```

`deploy/angie-guardian.conf` documents the fail-open toggle (what happens when
the sidecar is down) and the challenge/pass/denied routes.

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
raw flood. Every request still costs an `auth_request` subrequest and a store
lookup whether or not the client ever solves anything, and a client that
follows the challenge redirect also makes the sidecar issue and persist a
challenge. Under enough load the sidecar saturates and fail-open (the default)
sends the flood straight to your backend.

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
