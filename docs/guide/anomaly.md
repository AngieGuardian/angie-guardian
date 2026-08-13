# Train the Anomaly Model

The statistical anomaly scorer rates each unvouched request that reaches its
pipeline stage against a per-domain baseline learned from your own traffic.
Training and scoring normalize host case, ports, trailing dots, and bracketed
IPv6 the same way domain config lookup does, so equivalent host spellings use
one baseline. Valid PoW tokens short-circuit the scorer after WAF rule checks:
`deny` and `block` still apply, while `challenge` is already satisfied. With a
trained model in place, Guardian can challenge or deny
bot-shaped requests that no static WAF rule would catch, and scale the PoW
difficulty with the suspicion score.

## What training gives you

The trainer reads your access logs and writes one compact JSON artifact. Each
domain gets a domain-wide fallback plus bounded baselines for its busiest HTTP
method and first-path-segment combinations. Each baseline contains numeric
aggregates and two frequency tables; it records the *shape* of traffic, not
individual visitors, IPs, or sessions. In return, three things change at
runtime:

- **Bot-shaped requests can be caught without a WAF rule.** A scanner using a
  fresh path list, or probing a CVE nobody has written a rule for yet, still
  looks nothing like normal traffic for that host. The WAF has no rule to match;
  the scorer has an opinion anyway.
- **PoW difficulty scales with suspicion.** Instead of one flat difficulty for
  everyone, the score picks a point in `[base_difficulty, max_difficulty]`. A
  borderline client pays a cheap puzzle, an obvious bot pays an expensive one.
- **Ordinary visitors can stop seeing challenges entirely.** With
  `pow.mode: suspicion` the catch-all interstitial is off, so only requests the
  scorer (or an explicit WAF, GeoIP, or reputation rule) flags get challenged.

An enabled anomaly stage requires a configured, readable, valid model:
`guardiand -t` and startup fail otherwise, and every explicitly configured
domain that enables scoring must have a baseline in the artifact (so a
misspelled or under-trained domain cannot silently start unprotected). A
defaults-only policy can still receive unseen hosts: those requests are marked
as missing a baseline, the anomaly stage has no opinion, and the other
pipeline stages continue to apply.

## 1. Collect JSON access logs

The trainer does not parse Angie's default `combined` log format. It strictly
requires one JSON object per line with `host`, `method`, `uri`, `status`,
`user_agent`, and `guardian_action`. Extra fields are allowed, but missing,
duplicate, wrongly typed, malformed, or invalid required fields are counted as
bad input. A line over the 1 MiB input limit aborts the scan instead of being
silently skipped. [`deploy/angie-json-log.conf`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-json-log.conf) defines the matching
`guardian_json` format.

A `log_format` has to be declared in the `http {}` context, and can then be
referenced by name from any `access_log` directive. So it is two steps: include
the file once, then point each protected vhost's `access_log` at the format.

```nginx
# http {} context, once. Declares the guardian_json log_format:
include angie-json-log.conf;   # from deploy/angie-json-log.conf

# each protected server {} block: write that format to its own file.
# The second argument is the log_format name, not a path.
access_log /var/log/angie/example.com.access.json guardian_json;
```

Copy [the file](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-json-log.conf)
into place alongside the other snippets, then reload:

```sh
sudo cp deploy/angie-json-log.conf /etc/angie/
sudo angie -t && sudo systemctl reload angie
```

Per-vhost files make it obvious which traffic trained which baseline, but one
combined log also works: every record carries its own `host` field, and
`guardian-train` accepts either shape.

::: warning `$guardian_action` needs the Guardian protection include
The format logs `$guardian_action`, which is set by
`auth_request_set $guardian_action $upstream_http_x_guardian_action;` in
[`deploy/angie-guardian-location.conf`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/angie-guardian-location.conf).
For a request location that does not include the Guardian protection snippet,
the variable is empty and the strict trainer rejects that record. Wire up
[Angie](/guide/angie) first and confirm the log contains a Guardian action
before collecting the training window.
:::

Then wait. The baseline is only as good as the traffic behind it, so let logs
accumulate until each domain you care about has comfortably more records than
the `-min-requests` floor you plan to use in step 2. A few days of real traffic
is a reasonable starting point; a single quiet afternoon is not.

## 2. Train offline

Once JSON logs have accumulated, build and inspect a candidate per-domain
baseline offline. Promote it only after the checks described in the production
workflow. `guardiand` hot-swaps the configured artifact when the file changes,
so no restart is needed:

```sh
guardian-train train \
  -out model.candidate.json \
  -report training-report.json \
  -min-requests 5000 \
  -min-segment-requests 500 \
  -max-segments 128 \
  -max-invalid 0 \
  -require-domain example.com \
  /var/log/angie/*.access.json*
```

Plain and gzip-compressed files are accepted directly. The trainer makes a
bounded discovery pass for busy method/route segments, then a second exact pass
over the selected segments; each pass validates its input independently, so an
active log growing between them cannot introduce unchecked records, and the
training report describes the pass that produced the artifact. Filtering rules:

- Responses with status 400+ and requests Guardian challenged, denied or shed
  are excluded; malformed or schema-invalid lines count against `-max-invalid`.
- Domains below `-min-requests` and segments below `-min-segment-requests` are
  omitted (a thin sample is not a trustworthy baseline).
- Repeat `-require-domain` for every protected named domain so an omission
  rejects the candidate.

Before replacing an existing artifact, score a separate representative window
against both artifacts and reject surprising drift:

```sh
guardian-train compare \
  -current /etc/guardian/model.json \
  -candidate model.candidate.json \
  -report comparison-report.json \
  -min-requests 500 \
  -max-mean-delta 0.10 \
  -max-p95-delta 0.15 \
  /var/log/angie/validation/*.access.json.gz
```

For domains present in both artifacts, comparison fails on too little
validation data or mean/p95 drift beyond the limits. A retained but quiet
domain is reported as skipped rather than blocking the rest; a new candidate
domain is reported as added (there is no live score to compare). Removing a
live domain, or validation traffic covered by neither artifact, still rejects
the candidate. The reports make filtering, coverage, segment selection and
drift reviewable by automation and operators.

For production automation, prefer the shipped
[`guardian-train.service`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/guardian-train.service)
and
[`guardian-train.timer`](https://github.com/AngieGuardian/angie-guardian/blob/main/deploy/guardian-train.timer)
over a bare cron entry: weekly training from your retained log window, strict
input and expected-domain verification, candidate comparison, a kept last-good
artifact, and atomic promotion. See
[Running the anomaly trainer](/guide/production#running-the-anomaly-trainer)
for installation and the pause mechanism for incident windows.

## 3. Enable scoring

```yaml
domains:
  shop.example.com:
    pow: { enabled: true, mode: suspicion, base_difficulty: 5, max_difficulty: 6 }
    waf:
      anomaly:
        enabled: true
        model: /etc/guardian/model.json
        observe_only: true    # score and record metrics; do not challenge/deny
        challenge_at: 0.5     # score >= this -> PoW challenge
        deny_at: 0.85         # score >= this -> deny outright
```

With `pow.mode: suspicion`, the catch-all challenge is disabled. While
`observe_only` is true, anomaly scores are recorded but do not challenge or
deny. Explicit WAF, GeoIP, reputation, and attack-mode decisions still apply.
After tuning the thresholds, set `observe_only: false` (or remove it) to enforce
them. Scores from `challenge_at` through `1.0` scale PoW difficulty across
`[base_difficulty, max_difficulty]`; scores at or above `deny_at` are denied.

## How scoring works

Both the trainer and the scorer percent-decode the path and query string. The
scorer first chooses the most specific available baseline in this order:

1. HTTP method plus the first decoded path segment (`GET /products`)
2. first decoded path segment (`/products`)
3. HTTP method (`GET`)
4. the domain-wide fallback

This keeps a normal API `POST` or upload route from being judged against a
mostly-`GET` site average. The selected baseline then derives the same six
features from the path, query string, and User-Agent. Nothing else about the
client is involved.

| Feature | Learned as | What an outlier looks like |
| --- | --- | --- |
| Path depth (segment count) | mean + std | `/a/b/c/d/e/f/g` on a two-level site |
| Path length in bytes | mean + std | Overlong probe URIs |
| Path Shannon entropy | mean + std | Encoded or random-looking blobs |
| Query-field count (`&` separators + 1) | mean + std | Parameter-stuffed injection attempts |
| UA prefix (lowered, first 24 bytes) | frequency table | A UA absent from your real traffic |
| Path prefix (lowered, first two segments) | frequency table | A section of the site that does not exist |

The four numeric features score as a **z-score**: how many standard deviations
the request sits from the learned mean, saturating at four (past that, weirder
adds nothing). A floor on the standard deviation keeps a near-constant feature
from exploding on a small deviation. Truncating the lowered UA to its first 24
bytes is deliberate: it keeps a browser's version bumps from
turning every upgraded visitor into a rarity.

The two frequency tables score as **rarity**: a value making up 2% or more of
baseline traffic is fully ordinary, and one that never appears in the baseline
is fully rare. The tables keep only the top 1000 entries per baseline, which is
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

On the training side, a bounded heavy-hitter pass caps automatic segments per
domain and Welford keeps each segment's numeric aggregates at constant size,
but the frequency maps (pruned to the top 1000 only when training finishes)
and the set of observed domains grow with the input. A hostile,
high-cardinality log window can therefore still increase trainer memory: run
the job under the shipped memory-capped systemd sandbox and train only from
controlled Angie logs.

## Tune the thresholds

Use `GET /admin/score` to ask "how anomalous is this request?" and tune
`challenge_at` / `deny_at` against real request shapes. The endpoint returns the
combined score, not a per-feature explanation:

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
     "http://127.0.0.1:8072/admin/score?host=shop.example.com&method=GET&uri=/cgi-bin/x%3Fa=1&ua=curl/8"
# Example only; the score depends on your model:
# {"host":"shop.example.com","method":"GET","route":"/cgi-bin","baseline":"exact","scored":true,"score":0.72}
```

In `/metrics`:

- `guardian_anomaly_score` is the live per-domain score distribution for
  requests that reach the anomaly stage (requests terminated earlier,
  including valid PoW tokens, are not represented). With suspicion mode and
  `observe_only` it shows the remaining traffic's distribution without
  enforcing anything.
- `guardian_anomaly_baseline_selections_total` shows how often the exact,
  route, method and domain fallbacks are selected;
  `guardian_anomaly_baseline_misses_total` makes uncovered hosts visible.

The admin dashboard and `GET /admin/anomaly` expose configured coverage,
segment counts, training time and active artifact path without returning
baseline contents.

## Best practices

The detector is only as good as the traffic you train it on. A handful of habits
make the difference between a baseline that catches scanners and one that
annoys customers.

**Train on traffic that represents normal.** Frequent shapes in the window
become what the model considers ordinary (a single unusual record does not).
Include quiet hours as well as peaks, and avoid windows dominated by a one-off
event, a migration or a load test. After a large bot campaign, remember its
successful (sub-400) requests are in those logs too.

**Keep `-min-requests` honest.** The 5000 default is a floor, not a target: a
thin or unrepresentative sample produces a baseline that is too narrow, too
wide, or biased toward one traffic shape, so raising the floor on a busy site
beats trusting it. A domain dropped for insufficient data makes
`-require-domain` fail the job, and guardiand refuses startup or reload when
an explicitly configured domain has no baseline. Defaults-only traffic to an
unknown host stays fail-open for this stage but increments the
missing-baseline counter.

**Treat the artifact as perishable, but retrain deliberately.** Sites change
(new sections, a new mobile app UA, a redesign shifting every path prefix),
and Guardian hot-swaps the file within seconds but never expires a model on
its own, so a stale artifact slowly turns legitimate new traffic into
anomalies. That argues for revisiting the model, not regenerating it on a
tight timer: each retrain replaces the distribution you tuned your thresholds
against. Retrain when something changed that should change the baseline, and
recheck the score histogram afterwards. See
[Running the anomaly trainer](/guide/production#running-the-anomaly-trainer)
for the operational side, including why retraining over an attack window can
teach the baseline that the attack is normal.

**Roll out in observation mode first.** Set `observe_only: true` and watch the
`guardian_anomaly_score` histogram for a few days. Do not try to simulate this
with thresholds at `1.0`: comparisons are inclusive, so a score of exactly `1`
can still enforce. Pick thresholds from the observed distribution, then set
`observe_only: false` and reload.

**Move `challenge_at` before `deny_at`.** A challenge that misfires costs a
legitimate visitor a few seconds of PoW; a deny that misfires costs you the
visitor. Keep a comfortable gap between the two, and only tighten `deny_at`
after the score histogram shows a clean separation.

**Spot-check with `/admin/score` before changing a threshold.** Score the
request shapes you actually care about (a real browser request, your
monitoring probe, a partner's API client) and confirm each lands where you
expect. Health checks and uptime monitors are the classic false positive: an
unusual UA against a path that appears nowhere else in your traffic is
precisely the 0.55 combination described above.

**Give the trainer the whole picture.** Include all retained rotated logs
(plain and `.gz`) rather than only today's file; a combined multi-host stream
is fine since every record carries its own `host`. But reserve a
representative validation window for candidate comparison rather than
evaluating on the exact training sample.

::: tip A broken model fails startup, but not a reload
`guardiand` refuses to start on a missing or invalid artifact, on the grounds
that silently running without a configured protection is worse than not starting.
Once running, an invalid artifact or one missing a required named domain logs an
error and keeps the previous model. So a bad scheduled update degrades to a
stale baseline rather than an outage, but if you rotate the file out from under
a restart you will not come back up.
:::
