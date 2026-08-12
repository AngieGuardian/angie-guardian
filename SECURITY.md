# Security Policy

Angie Guardian is a WAF and proof-of-work bot firewall: it sits in the request
path of the sites it protects, so a vulnerability in it can have real impact.
Reports are taken seriously and handled quickly.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.** Public
disclosure before a fix is available puts every deployment at risk.

Instead, report it privately:

- **Email:** melroy@melroy.org, with `[angie-guardian security]` in the subject.
- **Matrix/Telegram:** PM me via [Matrix](https://matrix.to/#/@melroy:melroy.org) or [Telegram](https://t.me/melroyvandenberg).

Please include, as far as you can:

- the affected version (a release tag, or a commit hash),
- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- any suggested remediation.

## What to expect

- **Acknowledgement** within 3 working days.
- An initial **assessment** (severity, whether it's in scope) within about a
  week.
- A **fix and coordinated release** as fast as the severity warrants. You'll be
  kept updated on progress.
- **Credit** in the release notes for the fix, if you'd like it (let us know how
  you wish to be named, or if you'd rather stay anonymous).

We ask that you give us reasonable time to release a fix before any public
disclosure. We won't pursue or support legal action against good-faith research
that follows this policy.

## Supported versions

Guardian is pre-1.0 and moving quickly. Security fixes land on `main` and in the
next release; only the **latest release** is supported. Once 1.0 ships, this
section will state the supported release line.

## Scope

In scope: the `guardiand` sidecar, the WAF/PoW decision logic, the admin API,
the challenge/redeem flow, the token/JWT and key handling, and the deployment
glue in `deploy/`.

Out of scope (by design, documented in the
[security model](https://angieguardian.org/guide/threat-model)):

- volumetric / L3–L4 floods: that's Angie's rate limiting and your network's
  job, not a proof-of-work interstitial's;
- attacks originating from inside a configured allowlist / trusted range;
- a native-code solver outpacing browsers at proof-of-work (a cost trade-off,
  not a bypass);
- anything requiring control of the trusted `X-Guardian-*` headers, which is
  only possible if the sidecar's listener is misconfigured as client-reachable
  (Guardian refuses to start in that configuration unless you override it).
