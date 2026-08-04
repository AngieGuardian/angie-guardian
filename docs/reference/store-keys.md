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
| `block:` | Active IP blocks (the reason, plus a token identifying the write) | A blocked IP comes back unblocked | [`/admin/blocks`](/reference/admin-api#get-admin-blocks) and the dashboard's Active blocks panel, reason only |
| `blkct:` | Per-IP count of automatic blocks, 24h window | Repeat offenders restart at the first-offense `block_ttl` instead of a doubled one | [`/admin/blocks/{ip}`](/reference/admin-api#get-admin-blocks-ip) as `offenses`; cleared by an unblock unless `reset_backoff=false` |
| `ev:` | Per-IP behaviour counters, one key per event type (such as `rule_match`), unblock generation and window bucket | Progress toward an `ip_behaviour` threshold resets | Not surfaced; the current generation is rotated and its old keys are cleared by an unblock |
| `chesc:` | Per host+IP unsolved-issuance escalation | A client that farms challenges drops back to base difficulty | Not surfaced; the escalation itself is logged and counted in `guardian_challenges_total{outcome="escalated"}`, and an unblock clears it for one IP |
| `chfesc:` | As `chesc:`, but for framed navigations whose Fetch metadata cannot establish that the interstitial will render | A client farming challenges through a claimed frame context drops back to base difficulty | Not surfaced; counted in `guardian_challenges_total{outcome="frame_unscored"}`, and cleared by an unblock alongside `chesc:` |
| `chrl:` | Per-IP challenge issuance rate limit | An IP's issuance budget resets | Not surfaced |
| `botdns:` | Verified-crawler rDNS verdicts | Every crawler IP needs a fresh forward-confirmed DNS round trip | Not surfaced |
| `challenge:` | Issued challenge records and their spent markers | A solved challenge could be replayed until `challenge_ttl` elapsed | Not surfaced |
| `spent1:` | Single-spend markers for **stateless** challenges | As above, for challenges issued under attack mode | Not surfaced |
| `unblk:` | Marker that an unblock of this IP is recent or still running | A concurrent scorer could undo an unblock while it runs | Not surfaced; the store expires it a couple of seconds after the unblock finishes |
| `unblkgen:` | Identifies the most recent unblock of this IP | A block writer that stalls past the marker above could not tell that its block was overtaken by an unblock | Not surfaced; expires a day after the unblock that wrote it |
| `guardian-posture:` | Cross-instance attack posture votes | A replica would not see its peers' posture | [`/admin/attack`](/reference/admin-api#get-admin-attack) and the dashboard's attack panel |
| `guardian:health:probe:` | Per-process store liveness probe | `/readyz` could not distinguish a slow store from a broken one | [`/readyz`](/reference/admin-api#get-readyz) |

## Why most of it is not listable

Guardian reads its own state by a bounded set of exact keys on the hot path:
never by scanning a prefix. A normal block check is one `Get`; the rarer
behaviour-event path reads its unblock generation and performs one atomic
guarded increment against an exact counter key. Listing a prefix instead means
walking the keyspace, which on a loaded store is exactly the kind of scan that
must never land next to the auth path.

So the store deliberately offers a *dedicated index* for the one prefix that
needs enumerating rather than a general "list everything with this prefix"
call. `block:` has that index (the admin API and the nftables offload
reconciler both read it), and posture votes have their own bounded primitive.
Everything else is reachable only when you already know the key, which is why
per-IP views can show it and fleet-wide lists cannot.

`challenge:`, `spent1:` and `guardian:health:probe:` are additionally not worth
surfacing: they churn constantly and say nothing an operator acts on.

## Clearing a specific IP

[`DELETE /admin/blocks/{ip}`](/reference/admin-api#delete-admin-blocks-ip)
removes `block:`, clears `chesc:` and `chfesc:` for one address, rotates the
current `ev:` generation, and removes `blkct:` unless you ask it not to. It
cannot scan for the producer counters, so it rebuilds the old `ev:` keys from
every `(event type, window)` pair the running config can write and the
escalation keys from the hosts the decision ring saw this IP on plus the
configured vhosts. That covers what an operator lifting a block is actually
looking at, and the endpoint reports when it could not cover all of it.

`chesc:` and `chrl:` are counted through an in-process cache in front of the
store, so clearing one means clearing both copies. The unblock deletes the
shared copy synchronously so it can report whether that landed. One case it
cannot fix and therefore reports instead: while the cache is at capacity, an
unseen key is counted in a shared count-min sketch, and no per-key reset can
clear a sketch cell without corrupting every other key that hashes to it.

An unblock first writes `unblk:<ip>` and a fresh `unblkgen:<ip>` before clearing
the producer keys. While the first key lives, instances sharing the store
normally skip behaviour counting and automatic blocks for that IP. Its expiry
is enforced by the store, not an instance clock.

Correctness does not depend on that short marker surviving every round trip of
a slow reset. Every `ev:` key contains the generation that admitted its write.
At the end, one atomic store commit publishes a second fresh generation and
marker while removing `block:` and, when requested, `blkct:`. An event admitted
before that boundary may finish late, but only in an obsolete generation that
current traffic never reads.

Automatic blocks use the matching atomic operation in the other direction. In
one backend transaction (or Redis/Valkey script), Guardian verifies both the
generation and the previous `block:` value, advances `blkct:`, derives the
backoff TTL and writes the new block. A raced write therefore lands wholly
before the final unblock commit and is removed, or wholly after it and fails
without changing either key. The enforcement mirror validates the block's
owner token while serializing local add/remove notifications, so a delayed
notification cannot re-add an unblocked IP or overwrite a newer block.

The generation value is fresh, retained for a full day and never interpreted.
It is not a timestamp, so disagreeing instance clocks do not participate, and
it is not an incrementing counter whose old expiry could recreate a value a
parked writer had already seen.

Admin blocks are not gated by any of this: they do not go through the
scoreboard, so unblocking and then blocking by hand does what you asked.

## Reading a specific IP

The [IP lookup](/guide/admin) on the dashboard, and
[`GET /admin/blocks/{ip}`](/reference/admin-api#get-admin-blocks-ip) behind it,
resolve the exact keys for one address, which is why they can report block
state, expiry and the offense count without any scan.
