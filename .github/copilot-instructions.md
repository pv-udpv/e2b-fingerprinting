# Copilot Instructions — e2b-fingerprinting

> Loaded automatically by GitHub Copilot coding agent. Keep concise and specific.
> Primary language: **Python**. Default branch: `main`.

## Project intent

<!-- Maintainer: fill in 2-3 sentences on what this repo does. -->

## How to run locally

<!-- Maintainer: add setup + run commands. -->

## Language rules

- Prefer Python 3.11+ and keep code compatible with the version(s) this repo documents or configures.
- If linting/type-checking is configured, aim for `ruff` cleanliness and `mypy --strict`; if tests are added/configured, prefer `pytest` and fixtures over heavy mocking where possible.
- Keep module-level side effects to zero. No `import os; os.environ[...]=...` at import time.

## Commit & PR conventions

- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`).
- Small PRs. Prefer <400 lines of diff.
- If this repo uses a PR template, include `Why`, `Testing`, and `Risk` sections.
- If CI checks are present, do not disable or bypass them. Do not merge your own PR unless the maintainer explicitly asks.

## Tests

- If CI is configured, keep local verification aligned with it. If the repo pins a specific Python/Node version, use that version locally when practical.
- Snapshot tests: regenerate only when you intentionally changed output, and explain why in the PR.

## Secrets

- Never read secrets from the filesystem. If workflows are added, prefer `${{ secrets.XXX }}` for secret injection.
- Do not invent new secret names without coordinating with the maintainer.
- If you need a secret that doesn't exist, stop and open an issue instead of hardcoding.

### CI runner

- This repository may not define GitHub Actions workflows locally yet.
- If CI/workflows are added here, prefer GitHub-hosted runners by default.
- For minutes-expensive or long-running jobs, consider the self-hosted `[self-hosted, pv-cargo]` runner; see `pv-udpv/gh-runner-infra` for onboarding.

## What to avoid

- Don't touch `.github/workflows/` without an explicit ask — CI changes need human review.
- Don't introduce new runtime dependencies without justification.
- Don't rewrite unrelated code in the same PR. Keep the diff scoped.
- Don't assume `git push` auto-merges. Wait for review.
