# Admin API & Dashboard

The admin API and `/metrics` live on `admin.listen` (e.g. `127.0.0.1:8072`),
separate from the auth hot path. `/metrics` and `/healthz` are open; every
`/admin/*` route needs a bearer token.

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

## Everyday operations

```sh
TOKEN=$(cat /etc/guardian/admin.token)   # or your admin.token value
A=http://127.0.0.1:8072

# Is an IP currently blocked, and why?
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/blocks/203.0.113.9
# {"ip":"203.0.113.9","blocked":true,"reason":"threshold:signature"}

# List every currently active block, with reasons and expiry.
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/blocks

# What did the guardian just challenge or deny? Newest first, from an
# in-process ring buffer (per instance, cleared on restart).
curl -s -H "Authorization: Bearer $TOKEN" "$A/admin/decisions?action=deny&limit=20"

# A small "right now" rollup: active blocks, recent counts by action and
# reason category, and the PoW lifecycle (challenges issued/solved/failed +
# average solve seconds). (Long-horizon numbers live in /metrics.)
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/stats

# Block an IP for two hours (reason + ttl optional; default 15m).
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

# Rotate the Ed25519 signing key. Old tokens keep verifying until they
# expire, so nobody is logged out.
curl -s -H "Authorization: Bearer $TOKEN" -X POST $A/admin/rotate-key
# {"rotated":true}

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

Set `admin.dashboard: true`, start guardiand, and open the login link it
prints:

```
INFO admin dashboard ready url=http://127.0.0.1:8072/admin/dashboard#token=9f2c…
```

The token rides the URL **fragment**, which browsers never send over the
network; the page moves it into the tab's sessionStorage and scrubs it from
the address bar. (Opening the bare URL instead shows a paste-the-token gate.)

The dashboard shows active blocks (with one-click unblock and a block-an-IP
form), the recent deny/challenge feed (filterable by action and free text),
challenge lifecycle counters with the average solve time, per-domain feature
status, IP intelligence health (loaded GeoIP databases plus each reputation
feed's entries, refresh age and last error), and headline counters,
auto-refreshing every 5 seconds.

The page is a static shell: it stores no secrets and every data call goes to
the token-guarded `/admin/*` endpoints. It is **internal-only by
construction**: it lives on the admin listener, which refuses a non-loopback
bind without a configured token, and stays off unless enabled.
