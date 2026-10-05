# Repository agent policy

Skills live in `.agents/skills/`. Do not recreate duplicate `.claude/skills/`
copies; the `.agents` versions are canonical.

## Extended e2e must never enter GitLab CI/CD

The user deliberately excludes slow outage, real-time protocol timeout,
periodic probe-counter observation and abuse-soak qualification from CI/CD to
keep build/deploy cycles short.
**Never add `make e2e-extended`, `make e2e-angie-soak`, or equivalent slow-test
commands to `.gitlab-ci.yml`**, including scheduled, manual or release jobs.
Never enable `GUARDIAN_E2E_EXTENDED=1` or `ANGIE_HARDENING_SOAK=1` there.
Preserve the tests for explicit local qualification; do not remove their
assertions to shorten execution. The routine CI job uses `make e2e` only.

Read [the detailed execution policy](../test/e2e/AGENTS.md) before changing
e2e tests, the Makefile or `.gitlab-ci.yml`. Report routine and extended checks
separately; a routine pass is not evidence of extended coverage.
