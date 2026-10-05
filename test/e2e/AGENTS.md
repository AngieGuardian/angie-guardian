# E2E execution policy

The user deliberately moved slow real-time qualification out of CI/CD to
shorten routine build/deploy cycles. Preserve the tests and their assertions.

- `make e2e` is the routine integration suite and the only e2e CI job. It
  explicitly disables extended tests and the abuse soak, even when the caller
  has their environment flags set.
- `make e2e-extended` is explicit **local-only** qualification. It includes the
  routine suite plus store partition/crash/recovery, TLS handshake timeout,
  incomplete HTTP/1 headers/bodies, idle/stalled HTTP/1 resource cleanup, and
  the two-probe store-metric isolation observation.
- `make e2e-angie-soak` is a separate explicit **local-only** abuse soak.
- Do not add extended tests or the soak to push, merge-request, tag, scheduled,
  or manual CI/CD jobs. Do not set `GUARDIAN_E2E_EXTENDED=1` or
  `ANGIE_HARDENING_SOAK=1` in CI. Changing this policy requires an explicit user
  request; the value of the coverage is not permission to reintroduce it.
- Run extended qualification locally when changing store outage/recovery or
  Angie timeout/resource handling, and before releases affecting those paths.
  Report routine and extended results separately. A routine pass does not
  imply extended coverage passed.
- Keep ordinary request, WAF, PoW, admin, readiness, TLS negotiation and HTTP/2
  correctness tests in routine CI. Classify new long-running timeout/outage
  tests explicitly rather than growing the routine suite silently.

One local timing run on 2026-10-05 measured 203.7 seconds total. The original
four extended tests consumed 128.6 seconds, and the health test's two-probe
observation took approximately 19.1 seconds. The abuse soak was already opt-in
and skipped. These figures explain the policy, not a performance promise.
See `docs/guide/development.md` for commands and coverage.
