# Admin API & Dashboard

The admin API and `/metrics` live on `admin.listen` (e.g. `127.0.0.1:8072`),
separate from the auth hot path. `/metrics`, `/healthz`, and the optional static
`/admin/dashboard` shell are open; every JSON/data `/admin/*` route needs an
`Authorization: Bearer <token>` header with that exact scheme prefix. The
dashboard contains no data itself and authenticates every API call.

You never have to invent that token yourself. It resolves in this order:

1. `admin.token` (or the `ADMIN_TOKEN` env var), if set;
2. `admin.token_file`: auto-generated on first start (0600) and reused
   forever after, like the PoW signing key;
3. neither set: a loopback listener gets a fresh ephemeral token each start,
   printed in the startup log.

::: warning Non-loopback binds require a configured token
A non-loopback bind refuses to start without an explicitly configured token
(option 1 or 2 above).
:::

The admin listener is plain HTTP. Keep it on loopback or a strictly firewalled
management network. If it must cross a host or network boundary, place it
behind a TLS/mTLS reverse proxy or service mesh; a bearer token sent over
plaintext can be captured and replayed.

## Everyday operations

```sh
TOKEN=$(cat /etc/guardian/admin.token)   # or your admin.token value
A=http://127.0.0.1:8072

# Is an IP currently blocked, and why?
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/blocks/203.0.113.9
# {"ip":"203.0.113.9","blocked":true,"reason":"threshold:signature"}

# List a bounded page of active blocks, with reasons and expiry. The default
# is 1000 and the hard maximum is 10000; complete=false means more exist.
curl -s -H "Authorization: Bearer $TOKEN" "$A/admin/blocks?limit=1000"

# What did the guardian just challenge or deny? Newest first, from an
# in-process ring buffer (per instance, cleared on restart).
curl -s -H "Authorization: Bearer $TOKEN" "$A/admin/decisions?action=deny&limit=20"

# A small "right now" rollup: active blocks, recent counts by action and
# reason category, and the PoW lifecycle (challenges issued/solved/failed +
# average solve seconds). (Long-horizon numbers live in /metrics.)
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/stats

# Block an IP for two hours (reason + ttl optional; default 15m, max 8760h).
# Equivalent IPv6 spellings are canonicalized to one block.
curl -s -H "Authorization: Bearer $TOKEN" -X PUT \
     -d '{"reason":"manual abuse report","ttl":"2h"}' \
     $A/admin/blocks/203.0.113.9

# Lift a block.
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE $A/admin/blocks/203.0.113.9

# "Why would this request be challenged?" Score it against the domain's
# anomaly model, for tuning challenge_at / deny_at.
curl -s -H "Authorization: Bearer $TOKEN" \
     "$A/admin/score?host=shop.example.com&uri=/cgi-bin/x?a=1&ua=curl/8"
# {"host":"shop.example.com","scored":true,"score":0.72}

# Rotate the Ed25519 signing key. Requires previous_key_dir; shared live
# replicas refresh automatically and pre-rotation tokens remain valid for at
# most seven days. Older archive files are ignored in memory, not auto-deleted.
curl -s -H "Authorization: Bearer $TOKEN" -X POST $A/admin/rotate-key
# {"rotated":true}

# Reload guardian.yaml without a restart (same as sending SIGHUP). A config
# that fails validation is rejected and the running config stays active.
curl -s -H "Authorization: Bearer $TOKEN" -X POST $A/admin/reload
# {"reloaded":true}

# See which features are active per domain.
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/config

# IP intelligence status: GeoIP database types and build dates, plus every
# reputation feed's entry count, last refresh and last error.
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/intel

# What do we know about an IP? Country, ASN and feed membership, for testing
# geo rules and answering "why was this client denied".
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/intel/203.0.113.9
# {"ip":"203.0.113.9","enabled":true,
#  "info":{"country":"RU","asn":64500,"as_org":"Example Carrier"},
#  "feeds":[{"feed":"firehol-level1","action":"deny"}]}

# Prometheus scrape (no token needed).
curl -s $A/metrics | grep guardian_
```

The full endpoint list with request/response shapes is in the
[Admin API reference](/reference/admin-api).

## The reporting dashboard

Set `admin.dashboard: true`, start guardiand, and open the URL it prints:

```
INFO admin dashboard ready url=http://127.0.0.1:8072/admin/dashboard
```

Paste the token from `admin.token_file` (or your configured secret) into the
login gate. Guardian never puts configured or persistent bearer credentials
in process logs. The page keeps the token only in the tab's sessionStorage.

![The Guardian admin dashboard](/dashboard.png)

The dashboard shows active blocks (with one-click unblock and a block-an-IP
form), the recent deny/challenge feed (filterable by action and free text),
challenge lifecycle counters with the average solve time, per-domain feature
status, IP intelligence health (loaded GeoIP databases plus each reputation
feed's entries, refresh age and last error), and headline counters,
auto-refreshing every 5 seconds. The active-block table is capped at 1000 rows
and cached for one minute (and refreshed immediately after a block/unblock
action). The headline count comes from the bounded in-process mirror and is
shown as a lower bound when that mirror is capacity-incomplete, so leaving the
dashboard open never triggers an unbounded store scan.

The page is a static shell: it stores no secrets, stays off unless enabled,
and every data call goes to the token-guarded `/admin/*` endpoints. The shell
can still be publicly reachable on an external admin bind, so keep this
listener on loopback or a firewalled management network.
