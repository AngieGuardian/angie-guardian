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

## 1. Collect JSON access logs

Switch protected vhosts to the JSON access log format from
`deploy/angie-json-log.conf`:

```nginx
access_log /var/log/angie/example.com.access.json guardian_json;
```

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
