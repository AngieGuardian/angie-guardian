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
TOKEN=$(sudo cat /var/lib/guardian/admin.token)   # or your admin.token value
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
     "$A/admin/score?host=shop.example.com&method=GET&uri=/cgi-bin/x%3Fa=1&ua=curl/8"
# {"host":"shop.example.com","method":"GET","route":"/cgi-bin","baseline":"exact","scored":true,"score":0.72}

# Are every configured anomaly scope and loaded artifact covered?
curl -s -H "Authorization: Bearer $TOKEN" $A/admin/anomaly

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
status, anomaly baseline coverage and segment health, IP intelligence health
(loaded GeoIP databases plus each reputation feed's entries, refresh age and
last error), and headline counters. It
auto-refreshes on a selectable interval (2s to 60s, or off) chosen in the
header and remembered per browser. The active-block and recent-decision tables
paginate at 25 rows. The active-block table is capped at 1000 rows and cached
for one minute (and refreshed immediately after a block/unblock action). The
headline count comes from the bounded in-process mirror and is shown as a lower
bound when that mirror is capacity-incomplete, so leaving the dashboard open
never triggers an unbounded store scan.

When GeoIP or ASN databases are loaded, Recent decisions gains a **Geo** column
with the same country, locality, accuracy and network context as Top offenders.
Geo text participates in the free-text filter. Broad City-database matches are
dimmed and expose their accuracy radius on hover rather than presenting an
approximate locality as a precise one.

### Graphs

The page renders graphs with a local copy of Chart.js (no CDN). The charts are
drawn entirely from data the dashboard already fetches, at no cost to the hot
path:

- **Activity**: decisions over time (deny vs challenge) and by reason category,
  bucketed from the recent-decisions ring, plus the proof-of-work funnel
  (issued, solved, failed).
- **Distributions**: per-domain traffic volume, the solve-time histogram and
  the anomaly-score histogram, read from Prometheus histograms via
  [`GET /admin/distributions`](/reference/admin-api#get-admin-distributions).
  The histogram cards hide themselves until there is data.
- **Anomaly coverage**: loaded training times and artifact domain counts,
  configured scope coverage, route/method segment counts, selected fallback
  levels, and any missing
  baselines via [`GET /admin/anomaly`](/reference/admin-api#get-admin-anomaly)
  and the distribution counters.

### Top offenders

A ranked view of the heaviest sources of non-allow decisions in the recent
window (top IPs, reason categories and request paths, plus a country rollup
when GeoIP is loaded) from
[`GET /admin/offenders`](/reference/admin-api#get-admin-offenders). It counts
the in-process decision ring exactly, so it reflects challenged/denied traffic
(not allows) and adds nothing to the hot path.

With a City-class [`location_db`](/guide/bots-ip-intel#country-or-city-both-go-in-location-db)
the IP rows also name the city and region (`Schagen, NH · NL · KPN B.V.`). A
locality that GeoLite2 only resolves to a 200 km-or-wider circle is dimmed and
carries the radius in a tooltip, so a precise hit and a region-sized guess never
look alike. IPs with no city record show the country alone.

#### World map

When a `location_db` is loaded, a choropleth above the tables shades countries
by their share of non-allow decisions, drawn with a local copy of
chartjs-chart-geo and a bundled TopoJSON atlas (no CDN; the atlas is fetched
once, and only when there is geo data to draw). It uses an Equal Earth
projection so relative areas stay honest.

The map can be explored without trapping normal page scrolling. On Linux and
Windows, hold **Ctrl** while using the mouse wheel to zoom or dragging to pan;
on macOS use **Cmd**. Touch screens support direct one-finger panning and
two-finger pinch zoom. **Reset view** returns to the centred world view. The
zoom plugin and its touch-gesture dependency are bundled with the daemon, so
these controls also work in air-gapped deployments.

The atlas has no shape for some countries, mostly city-states and small island
territories such as Hong Kong, Singapore and Malta. Their traffic is **not**
dropped: it is listed under the map as `Not on map: HK 4 · SG 3`. The country
table beside the map remains the complete, exact view.

### Server traffic (Angie API)

Guardian never sees allowed traffic on its stateless hot path, so real
per-domain request counts, live in-flight connections, response-code mix and
bandwidth can only come from Angie itself. Point guardiand at Angie's HTTP API
with `admin.angie_api` and the dashboard grows a **Server traffic** section
reading it through [`GET /admin/angie`](/reference/admin-api#get-admin-angie).
See [Enabling the Angie API](#enabling-the-angie-api) below. The section hides
itself when unconfigured and shows "Angie API unreachable" (without breaking the
rest of the page) when Angie's API is down.

The page is a static shell: it stores no secrets, stays off unless enabled,
and every data call goes to the token-guarded `/admin/*` endpoints. The shell
can still be publicly reachable on an external admin bind, so keep this
listener on loopback or a firewalled management network.

## Enabling the Angie API

The **Server traffic** dashboard panels read Angie's own [HTTP API][angie-api]:
statistics Guardian structurally cannot collect, since it deliberately does not
record the allow path. guardiand fetches the API server-side and relays it
behind the admin token, so **Angie's API never needs to be exposed**; keep it
on loopback.

[angie-api]: https://en.angie.software/angie/docs/configuration/modules/http/http_api/

Two steps, both on the Angie side. First, add a `status_zone` to each protected
server (and, for per-path counters, to locations) so their traffic is counted:

```nginx
server {
    server_name example.com;
    status_zone $host;          # one zone per virtual host
    # ...
    location /api/ {
        status_zone api;        # optional per-location counter
        # ...
    }
}
```

Second, expose the API on a **loopback-only** listener:

```nginx
# In the http {} context.
server {
    listen 127.0.0.1:81;
    allow 127.0.0.0/8;
    allow ::1/128;
    deny all;                   # defence in depth; the bind is already loopback

    location /status/ {
        api /status/;
    }
}
```

A ready-to-include version of this is in
[`deploy/angie-status.conf`](https://gitlab.melroy.org/melroy/angie-guardian/-/blob/main/deploy/angie-status.conf).

Then point guardiand at it:

```yaml
admin:
  angie_api:
    url: http://127.0.0.1:81/status   # matches the api location above
    timeout: 2s                        # per-fetch cap (default 2s)
```

::: warning Keep the Angie API on loopback
The API exposes traffic statistics and, depending on configuration, can expose
more. guardiand reads it server-side and relays only the traffic zones to the
dashboard behind the admin token, so there is no reason to bind the API to a
public interface. In production, keep it on `127.0.0.1` (or a firewalled
management interface) exactly as shown.
:::

The relay is a plain read of another local service; it is never on Guardian's
request hot path. Only fixed API paths are fetched (no request-controlled
target), each with a short timeout, no redirect following, a capped response
read, and a ~3-second cache so several open dashboard tabs do not multiply load
on Angie. A missing `location_zones` (no location has a `status_zone`) is fine:
the per-domain server zones still show.
