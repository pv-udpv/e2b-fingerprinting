# Copilot Instructions — e2b-fingerprinting

> Loaded automatically by GitHub Copilot coding agent. Keep concise and specific.
> Primary language: **Python**. Default branch: `main`.

## Project intent

<!-- Maintainer: fill in 2-3 sentences on what this repo does. -->

## How to run locally

<!-- Maintainer: add setup + run commands. -->

## Language rules

- Python 3.11+ required. Target `ruff` clean + `mypy --strict` where configured.
- Use `pytest` for tests; prefer fixtures over mocks where possible.
- Keep module-level side effects to zero. No `import os; os.environ[...]=...` at import time.

## Commit & PR conventions

- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`).
- Small PRs. Prefer <400 lines of diff.
- Every PR needs a `Why`, `Testing`, and `Risk` section (matches `pull_request_template.md`).
- Do NOT disable CI checks. Do NOT merge your own PR.

## Tests

- Running tests locally must match CI. If CI uses a specific Python/Node version, pin it.
- Snapshot tests: regenerate only when you intentionally changed output, and explain why in the PR.

## Secrets

- Never read secrets from the filesystem. Use `${{ secrets.XXX }}` in workflows.
- Do not invent new secret names without coordinating with the maintainer.
- If you need a secret that doesn't exist, stop and open an issue instead of hardcoding.

### CI runner

- This repo currently runs CI on GitHub-hosted runners.
- For minutes-expensive or long-running jobs, prefer migrating to the self-hosted `[self-hosted, pv-cargo]` runner. See `pv-udpv/gh-runner-infra` for onboarding.

## What to avoid

- Don't touch `.github/workflows/` without an explicit ask — CI changes need human review.
- Don't introduce new runtime dependencies without justification.
- Don't rewrite unrelated code in the same PR. Keep the diff scoped.
- Don't assume `git push` auto-merges. Wait for review.
