# Store keys

What Guardian keeps in the shared store, and which of it an operator can see.

Every key is TTL'd, so nothing grows without bound. All of it survives a
restart on a durable backend (`pebble`, `buntdb`, `redis`/`valkey`) and is lost
on `memory`, which is what makes `memory` an evaluation backend rather than a
production one.

This page exists because the answer is not obvious from the dashboard: only two
of these prefixes are enumerable, and only enumerable state can be listed.

## The keyspace

| Prefix | Holds | Losing it would mean | Visible where |
|---|---|---|---|
| `block:` | Active IP blocks | A blocked IP comes back unblocked | [`/admin/blocks`](/reference/admin-api#get-admin-blocks) and the dashboard's Active blocks panel |
| `blkct:` | Per-IP count of automatic blocks, 24h window | Repeat offenders restart at the first-offense `block_ttl` instead of a doubled one | [`/admin/blocks/{ip}`](/reference/admin-api#get-admin-blocks-ip) as `offenses` |
| `ev:` | Per-IP behaviour counters, one key per event type and window bucket | Progress toward an `ip_behaviour` threshold resets | Not surfaced |
| `chesc:` | Per host+IP unsolved-issuance escalation | A client that farms challenges drops back to base difficulty | Not surfaced; the escalation itself is logged and counted in `guardian_challenges_total{outcome="escalated"}` |
| `chrl:` | Per-IP challenge issuance rate limit | An IP's issuance budget resets | Not surfaced |
| `botdns:` | Verified-crawler rDNS verdicts | Every crawler IP needs a fresh forward-confirmed DNS round trip | Not surfaced |
| `challenge:` | Issued challenge records and their spent markers | A solved challenge could be replayed until `challenge_ttl` elapsed | Not surfaced |
| `spent1:` | Single-spend markers for **stateless** challenges | As above, for challenges issued under attack mode | Not surfaced |
| `guardian-posture:` | Cross-instance attack posture votes | A replica would not see its peers' posture | [`/admin/attack`](/reference/admin-api#get-admin-attack) and the dashboard's attack panel |
| `guardian:health:probe:` | Per-process store liveness probe | `/readyz` could not distinguish a slow store from a broken one | [`/readyz`](/reference/admin-api#get-readyz) |

## Why most of it is not listable

Guardian reads its own state by exact key on the hot path: one `Get` for a
block check, one `Incr` for a counter. Listing a prefix instead means walking
the keyspace, which on a loaded store is exactly the kind of scan that must
never land next to the auth path.

So the store deliberately offers a *dedicated index* for the one prefix that
needs enumerating rather than a general "list everything with this prefix"
call. `block:` has that index (the admin API and the nftables offload
reconciler both read it), and posture votes have their own bounded primitive.
Everything else is reachable only when you already know the key, which is why
per-IP views can show it and fleet-wide lists cannot.

`challenge:`, `spent1:` and `guardian:health:probe:` are additionally not worth
surfacing: they churn constantly and say nothing an operator acts on.

## Reading a specific IP

The [IP lookup](/guide/admin) on the dashboard, and
[`GET /admin/blocks/{ip}`](/reference/admin-api#get-admin-blocks-ip) behind it,
resolve the exact keys for one address, which is why they can report block
state, expiry and the offense count without any scan.
