# Gauntlet GitHub Action

Fire the adversarial suite at your agent on every push/PR and **fail the build**
when it leaks, takes an unsafe action, crashes, or drifts out of scope. On pull
requests it posts (and keeps updating) a report comment.

## Usage

```yaml
# .github/workflows/agent-reliability.yml
name: agent-reliability
on: [pull_request]

permissions:
  contents: read
  pull-requests: write        # needed for the PR comment

jobs:
  gauntlet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }

      # Bring your agent up however you like (or point at a deployed staging URL).
      # - run: ./scripts/start-staging-agent.sh

      - uses: GauntletVectorLabs/gauntlet/.github/actions/gauntlet@main
        with:
          target: ${{ secrets.STAGING_AGENT_URL }}
          canaries: canaries.json
          fail-on: HIGH
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `target` | — (required) | Agent HTTP endpoint (POST, JSON in/out). |
| `canaries` | `""` | Path to a canaries JSON (what your agent must never do). |
| `fail-on` | `HIGH` | Gate severity: `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`. |
| `request-field` | `message` | JSON field the probe goes in. |
| `response-field` | `response` | JSON field to read the reply from. |
| `header` | `""` | One extra request header, `Key: Value` (e.g. an auth token). |
| `comment` | `true` | Post/update a PR comment with the report. |
| `version` | `gauntlet-agent` | PyPI spec to install (ignored when this repo's package is checked out). |

The step exits nonzero — failing the job — when any finding is at or above
`fail-on`. That's your gate.

## Notes

- **Availability:** until `gauntlet-agent` is published to PyPI and this repo is
  public, external `uses:` references can't resolve. Within this monorepo the
  action installs from `packages/gauntlet` directly (see `action-selftest.yml`).
- **Hosted alternative:** if you use the dashboard, trigger a run instead and let
  it track regressions across builds:
  ```yaml
  - run: |
      curl -X POST "$DASH/api/runs" \
        -H "Authorization: Bearer ${{ secrets.GAUNTLET_KEY }}" \
        -d target=${{ secrets.STAGING_AGENT_URL }} -d gate=HIGH
  ```
