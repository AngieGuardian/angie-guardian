# Block Enforcement Offload

Once Guardian decides an IP is bad, every later request from it must be
denied. Enforcing that check as cheaply as possible matters under attack: a
flood from already-blocked clients should cost near nothing, not saturate the
sidecar and trip [fail-open](/guide/threat-model#fail-open-by-design).

Guardian enforces blocks on two layers:

1. an always-on **in-process mirror**, so the block check on the hot path is a
   memory lookup with no store read;
2. an optional **nftables sink** (Linux) that drops a blocked client's packets
   in the kernel before Angie runs the auth subrequest at all.

Both are configured under the top-level `enforcement:` key. Neither changes
which IPs get blocked (the [behavioural scoreboard](/reference/configuration#waf-ip-behaviour),
WAF `block` rules and the admin API still decide that); they change how
cheaply an existing block is enforced.

## The in-process mirror

Behavioural blocks live in the [store](/guide/production#choosing-a-store-backend)
with a TTL. Without the mirror, every single request pays a store `Get` to
check that key, so a flood from a blocked IP hammers the store on the hot
path. The mirror is a bounded in-memory copy of the active block set:

- **Write-through.** Every block and unblock (scoreboard, WAF, admin API)
  updates the mirror synchronously, so enforcement is immediate.
- **Reconciled and bounded.** A periodic active-block index read
  (`reconcile_interval`, default 10s) seeds the mirror at startup, corrects
  entries and picks up blocks placed by another instance. Reconciliation
  retains at most `max_entries`. Memory has a dedicated block map, the embedded
  backends (buntdb, pebble) seek directly to their ordered `block:` range, and
  Redis reads a fixed sorted-set index, so unrelated challenge/counter keys
  never increase tick cost.
- **Store-outage safe.** A mirror hit denies even while the store is down, so
  an outage no longer silently drops behavioural blocks.

For the embedded backends (`memory`, `buntdb`, `pebble`) the seeded mirror is
**authoritative**: after the first scan the per-request store read disappears
entirely, for blocked and clean traffic alike. For a shared store (`redis`)
the mirror is **read-through**: a miss still consults the store so a block
placed by another replica bites before the next scan, and the discovered
block is cached back so the flood's next request is free. `mode: auto`
(the default) picks the right one from your store backend.

That read-through consult is one store round-trip per request, and on a
networked store it dominates the allow/token path: it is why a
single-instance embedded backend (authoritative, zero reads) measures roughly
twice the read throughput of redis (see the
[performance numbers](/guide/load-testing#benchmark-results)). The trade is
deliberate: that read is what makes a block placed on one replica apply on the
others within microseconds instead of up to one `reconcile_interval`. If you
prefer the speed and can accept the cross-replica lag, set
`enforcement.mirror.mode: authoritative` explicitly on redis (measured ~183k
vs ~94k req/s on the allow path); blocks from other replicas then apply only
after the next indexed reconcile, and a shorter `reconcile_interval` narrows
that lag at the cost of more frequent bounded active-block reads.

If the mirror fills past `max_entries` (default ~1M), its status becomes
`complete: false` and misses fall back to the store read path even in
`authoritative` mode; reconciliation stops retaining results at the same
bound. Enforcement is never lost, only the optimization, and each dropped
insertion counts in
`guardian_offload_ops_total{sink="mirror",status="dropped"}`. Size the mirror
above the expected active-block high-water mark: sustained incompleteness
turns clean requests back into store traffic by design.

The mirror has no on/off switch: it is strictly cheaper than the store lookup
it replaces and degrades to it in every failure mode.

## The nftables sink

The mirror still costs one auth subrequest per blocked request (Angie asks,
the sidecar answers "deny" from memory). The nftables sink removes even that:
it programs blocked IPs into a kernel set, so their packets are dropped by the
kernel and Angie never sees them. This is opt-in, Linux only, and needs
`CAP_NET_ADMIN` in the network namespace where client traffic arrives.

```yaml
enforcement:
  nftables:
    enabled: true
    mode: managed          # managed | sets_only
    table: guardian
    hook: input            # input | prerouting
    ports: [80, 443]
    max_entries: 65536
    never_block:           # your load balancer / CDN ranges
      - 203.0.113.0/24
```

- **`managed` (default)** creates a table with one drop rule per address
  family, matching only the source-in-the-set **and** the configured `ports`.
  Scoping to ports is the safety mechanism: SSH and the admin listener are out
  of reach of the drop rule by construction, so a block can never lock you out
  of the box.
- **`sets_only`** just maintains the sets `guardian_block4` / `guardian_block6`
  and leaves the ruleset to you: reference `@guardian_block4` and
  `@guardian_block6` from your own nftables config.

Every element is added with a **per-element kernel timeout** equal to the
block's remaining TTL. If guardiand crashes, the kernel expires the blocks on
its own; there is no stuck-forever rule.

### The never_block safety filter

Before any address is sent to the kernel, the sink drops it from the batch if
it is:

- loopback, link-local, private or special-purpose (RFC1918, the
  `100.64.0.0/10` CGNAT range, IPv6 ULA, unspecified, multicast);
- in a `never_block` CIDR;
- in **any** configured
  [`allowlist`](/reference/configuration#allowlist-denylist), across defaults,
  domains and path overlays (the kernel sees neither Host nor path, so
  allowlist entries must win globally at this layer).

Private and special-purpose ranges are withheld by default because a
misconfigured trusted proxy surfacing an internal hop (a bridge gateway, an LB
backend) as the client IP would otherwise kernel-drop your own infrastructure,
and in `managed` mode that block outlives a daemon restart via its kernel
timeout. If Guardian genuinely serves routable private space, set
`enforcement.nftables.allow_private: true`; loopback and link-local stay
excluded regardless.

::: danger Put your load balancer and CDN ranges in never_block
The drop is at layer 3. If a request from behind a load balancer or CDN
carries that proxy's own address as the source, dropping it takes down
**everything** behind that address. Always list your LB/CDN ranges in
`never_block`.
:::

### Network namespaces

The kernel set must live in the namespace where client packets arrive, which
is not necessarily guardiand's own.

- **Bare metal / host-network Angie**: guardiand on the host is already in the
  right namespace. Grant the capability in the systemd unit (commented lines
  in [`deploy/guardiand.service`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/guardiand.service)):

  ```ini
  AmbientCapabilities=CAP_NET_ADMIN
  CapabilityBoundingSet=CAP_NET_ADMIN
  RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
  ```

- **Docker Compose**: client traffic arrives in Angie's namespace, so run
  guardiand there. See
  [`deploy/docker/compose.nft.yaml`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/docker/compose.nft.yaml):
  `network_mode: "service:angie"` plus `cap_add: [NET_ADMIN]`, with Angie
  reaching the sidecar at `127.0.0.1:8071`.

- **Explicit namespace**: point `enforcement.nftables.netns` at a namespace
  file (e.g. a bind-mounted `/proc/<pid>/ns/net`) to program a different
  namespace than guardiand's own.

If the capability or the `nf_tables` kernel module is missing, the sink logs
once, reports unhealthy, and keeps retrying on each reconcile tick; the mirror
and store paths keep enforcing in the meantime. Nothing in the offload path
can ever error a request.

## Why not push blocks into Angie itself?

Open-source Angie cannot accept dynamic block updates without a reload: its
built-in [API module](https://en.angie.software/angie/docs/configuration/modules/http/http_api/)
is read-only (the writable `/config` API is Angie PRO only), the
[keyval module](https://en.angie.software/angie/docs/installation/external-modules/keyval/)
is a third-party add-on without TTL support, and a `deny`-include plus reload
would storm reloads as blocks churn under attack. So Guardian enforces in its
own memory and, when asked, in the kernel rather than in Angie's
configuration.

## Observability

`GET /admin/offload` reports the mirror (mode, entry count, seed and
`complete` state, last reconcile) and every sink's health, and
`POST /admin/offload/reconcile` forces an immediate indexed reconcile for drift
repair after a manual `nft flush`.

Metrics (all bounded-cardinality):

| Metric | What it tells you |
|---|---|
| `guardian_block_lookups_total{source,outcome}` | mirror vs store hits/misses: proves the fast path works |
| `guardian_offload_entries{sink}` | active entries in the mirror and each sink |
| `guardian_offload_ops_total{sink,op,status}` | add/remove operations and drops |
| `guardian_offload_reconcile_total{status}` | indexed reconciles, ok vs error |
| `guardian_offload_reconcile_skipped_total{reason}` | sink replace-all repair skipped for an incomplete snapshot or concurrent event |
| `guardian_offload_healthy{sink}` | 1 = sink enforcing, 0 = degraded to in-daemon |

Alert on `guardian_offload_healthy{sink="nftables"} == 0`: it means kernel
enforcement broke and you are back to in-daemon enforcement.
Also alert when `rate(guardian_offload_reconcile_skipped_total[5m])` remains
non-zero while `guardian_offload_ops_total{status="dropped"}` increases: event
queue drift is then waiting for a quiet, complete replace-all repair.

## Configuration reference

See [Configuration Options → enforcement](/reference/configuration#enforcement)
for every field, default and constraint.
