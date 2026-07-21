# Train the Anomaly Model

The statistical anomaly scorer rates each unvouched request that reaches its
pipeline stage against a per-domain baseline learned from your own traffic.
Training and scoring normalize host case, ports, trailing dots, and bracketed
IPv6 the same way domain config lookup does, so equivalent host spellings use
one baseline. Valid PoW tokens short-circuit the scorer after signature checks:
`deny` and `block` still apply, while `challenge` is already satisfied. With a
trained model in place, Guardian can challenge or deny
bot-shaped requests that no static signature would catch, and scale the PoW
difficulty with the suspicion score.

## What training gives you

The trainer reads your access logs and writes one small JSON artifact: a
**per-domain baseline** of roughly ten numbers plus two frequency tables. It
records the *shape* of your traffic in aggregate, not individual visitors, IPs,
or sessions. In return, three things change at runtime:

- **Bot-shaped requests get caught without a signature.** A scanner using a
  fresh path list, or probing a CVE nobody has written a rule for yet, still
  looks nothing like normal traffic for that host. The WAF has no rule to match;
  the scorer has an opinion anyway.
- **PoW difficulty scales with suspicion.** Instead of one flat difficulty for
  everyone, the score picks a point in `[base_difficulty, max_difficulty]`. A
  borderline client pays a cheap puzzle, an obvious bot pays an expensive one.
- **Ordinary visitors can stop seeing challenges entirely.** With
  `pow.mode: suspicion` the catch-all interstitial is off, so only requests the
  scorer (or an explicit WAF, GeoIP, or reputation rule) flags get challenged.

Without a model the stage is inert: `anomaly.enabled: true` with no artifact, or
a host that is absent from the artifact, scores `0`. No baseline, no opinion, and
the request continues to the other pipeline stages unchanged.

## 1. Collect JSON access logs

The trainer does not parse Angie's default `combined` log format. It reads one
JSON object per line and needs four fields per record: `host`, `uri`,
`user_agent`, and `status`. `deploy/angie-json-log.conf` defines a `log_format`
named `guardian_json` that emits exactly those (plus timestamp, client address,
method, bytes, request time, referer, and Guardian's own action, which are
useful for your own analysis and ignored by the trainer).

A `log_format` has to be declared in the `http {}` context, and can then be
referenced by name from any `access_log` directive. So it is two steps: include
the file once, then point each protected vhost's `access_log` at the format.

```nginx
# http {} context, once. Declares the guardian_json log_format:
include /etc/angie/angie-json-log.conf;   # from deploy/angie-json-log.conf

# each protected server {} block: write that format to its own file.
# The second argument is the log_format name, not a path.
access_log /var/log/angie/example.com.access.json guardian_json;
```

Copy the file into place alongside the other snippets, then reload:

```sh
sudo cp deploy/angie-json-log.conf /etc/angie/
sudo angie -t && sudo systemctl reload angie
```

Why a per-vhost log file rather than one shared log: the baseline is per domain,
and separate files make it obvious which traffic trained which baseline. One
combined file also works, since every record carries its own `host` field, and
you can pass either shape to `guardian-train`.

::: warning `$guardian_action` needs the Guardian snippet
The format logs `$guardian_action`, which is set by
`auth_request_set $guardian_action $upstream_http_x_guardian_action;` in
`deploy/angie-guardian.conf`. In a `server {}` block that does not include the
Guardian snippet the variable is simply empty, which logs fine but tells you
nothing. Wire up [Angie](/guide/angie) first.
:::

Then wait. The baseline is only as good as the traffic behind it, so let logs
accumulate until each domain you care about has comfortably more records than
the `-min-requests` floor you plan to use in step 2. A few days of real traffic
is a reasonable starting point; a single quiet afternoon is not.

## 2. Train offline

Once JSON logs have accumulated, build a per-domain baseline offline and drop
it where the config's `anomaly.model` points. `guardiand` hot-swaps the
artifact when the file changes, no restart needed:

```sh
guardian-train -out /etc/guardian/model.json \
               -min-requests 5000 \
               /var/log/angie/*.access.json

# From a stream (e.g. journald, or gzip'd logs):
zcat /var/log/angie/example.com.access.json.*.gz | guardian-train -out model.json -
```

Re-run it from cron; `guardiand` picks up each new model within seconds.
Records without a host and responses with status >= 400 are excluded, so
scanner/error traffic does not become the normal baseline. Domains below
`-min-requests` usable successful records are dropped (a thin baseline
misclassifies everything).

## 3. Enable scoring

```yaml
domains:
  shop.example.com:
    pow: { enabled: true, mode: suspicion, base_difficulty: 5, max_difficulty: 6 }
    waf:
      anomaly:
        enabled: true
        model: /etc/guardian/model.json
        challenge_at: 0.5     # score >= this -> PoW challenge
        deny_at: 0.85         # score >= this -> deny outright
```

With `pow.mode: suspicion`, the catch-all challenge is disabled. In this
example the anomaly scorer is the only challenge policy, so ordinary visitors
never see an interstitial; explicit WAF, GeoIP, or reputation challenge rules
would still apply. Difficulty scales across `[base_difficulty, max_difficulty]`
with the score, so a more bot-like client pays more.

## How scoring works

Both the trainer and the scorer derive the same six features from a request,
using only the host, path, query string, and User-Agent. Nothing else about the
client is involved.

| Feature | Learned as | What an outlier looks like |
| --- | --- | --- |
| Path depth (segment count) | mean + std | `/a/b/c/d/e/f/g` on a two-level site |
| Path length in bytes | mean + std | Overlong probe URIs |
| Path Shannon entropy | mean + std | Encoded or random-looking blobs |
| Query parameter count | mean + std | Parameter-stuffed injection attempts |
| UA prefix (lowered, first 24 chars) | frequency table | A UA absent from your real traffic |
| Path prefix (first two segments) | frequency table | A section of the site that does not exist |

The four numeric features score as a **z-score**: how many standard deviations
the request sits from the learned mean, saturating at four (past that, weirder
adds nothing). A floor on the standard deviation keeps a near-constant feature
from exploding on a small deviation. Truncating the UA to its first 24
lowercased characters is deliberate: it keeps a browser's version bumps from
turning every upgraded visitor into a rarity.

The two frequency tables score as **rarity**: a value making up 2% or more of
baseline traffic is fully ordinary, and one that never appears in the baseline
is fully rare. The tables keep only the top 1000 entries per domain, which is
safe because everything pruned is by definition rare, and "absent" already means
"rare" to the scorer.

The six feature scores combine into a weighted sum capped at `1.0`:

- path shape (depth, length, and entropy averaged together): **0.35**
- UA rarity: **0.30**
- path-prefix rarity: **0.25**
- query parameter count: **0.10**

That weighting explains the thresholds. An unknown UA hitting a section of the
site that does not exist scores `0.55` on those two features alone, which clears
a `challenge_at` of `0.5` without any help from path shape. Reaching a
`deny_at` of `0.85` effectively requires the path to be misshapen as well, so
denial stays reserved for requests that are wrong in several ways at once.

On the training side, aggregation uses Welford streaming statistics, so memory
stays flat regardless of how much log you feed in; only the frequency tables
grow, and `Finish` prunes those. Records with no host, and any response with
status >= 400, are skipped. That exclusion matters: the scanners already probing
your site are mostly generating 404s, and counting them would teach the baseline
that scanner traffic is normal.

## Tune the thresholds

Use `GET /admin/score` to ask "why would this request be challenged?" and tune
`challenge_at` / `deny_at` against real request shapes:

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
     "http://127.0.0.1:8072/admin/score?host=shop.example.com&uri=/cgi-bin/x?a=1&ua=curl/8"
# {"host":"shop.example.com","scored":true,"score":0.72}
```

The `guardian_` anomaly-score histogram in `/metrics` shows the live score
distribution per domain, which makes threshold drift easy to spot.

## Best practices

The detector is only as good as the traffic you train it on. A handful of habits
make the difference between a baseline that catches scanners and one that
annoys customers.

**Train on traffic that represents normal.** The baseline defines "ordinary" for
a domain, so anything unusual present in the training window becomes ordinary,
and anything normal but absent becomes suspicious. Train on a window that
includes your quiet hours as well as your peak, and avoid windows dominated by a
one-off event, a migration, or a load test. If you have just survived a large
bot campaign, note that the campaign's successful (sub-400) requests are in
those logs too.

**Keep `-min-requests` honest.** The 1000 default is a floor, not a target. Low
traffic domains produce wide, mushy distributions in which almost nothing looks
anomalous, so raising the floor for a busy site (the guide's example uses 5000)
is usually better than training a baseline you cannot trust. A domain dropped
for thin data simply scores 0, which is a safe outcome.

**Treat the artifact as perishable, but retrain deliberately.** Sites change:
new sections, a new mobile app UA, a redesign that shifts every path prefix.
Guardian hot-swaps the file within seconds of it changing but never expires a
model on its own, so a stale artifact stays trusted indefinitely and slowly
turns legitimate new traffic into anomalies. That argues for revisiting the
model, not for regenerating it on a tight timer: each retrain replaces the
distribution you tuned your thresholds against. Retrain when something changed
that should change the baseline, and recheck the score histogram afterwards.
See [Running the anomaly trainer](/guide/production#running-the-anomaly-trainer)
for the operational side, including why retraining over an attack window can
teach the baseline that the attack is normal.

**Roll out in observation mode first.** Before enforcing, set `challenge_at` and
`deny_at` high enough that nothing trips, and watch the `/metrics` score
histogram for a few days. It shows you the real distribution per domain, which
is the only honest basis for picking thresholds. Then lower `challenge_at` to
where the tail begins.

**Move `challenge_at` before `deny_at`.** A challenge that misfires costs a
legitimate visitor a few seconds of PoW; a deny that misfires costs you the
visitor. Keep a comfortable gap between the two, and only tighten `deny_at`
after the score histogram shows a clean separation.

**Spot-check with `/admin/score` before changing a threshold.** Replay the
shapes you actually care about, a real browser request, your monitoring
probe, a partner's API client, and confirm each lands where you expect. Health
checks and uptime monitors are the classic false positive: they often use an
unusual UA against a path that appears nowhere else in your traffic, which is
precisely the 0.55 combination described above.

**Give the trainer the whole picture.** Point it at all rotated logs for a
domain, including compressed ones, rather than only today's file. Feeding a
combined multi-host log is fine, since each record carries its own `host`.

::: tip A broken model fails startup, but not a reload
`guardiand` refuses to start on a missing or invalid artifact, on the grounds
that silently running without a configured protection is worse than not starting.
Once running, a failed reload logs an error and keeps the previous model. So a
bad cron run degrades to a stale baseline rather than an outage, but if you
rotate the file out from under a restart you will not come back up.
:::
