# Releasing `gauntlet-agent` to PyPI

Publishing uses **Trusted Publishing** (OIDC) — no API token is stored. The
release workflow (`.github/workflows/release.yml`) builds and publishes whenever
you push a `v*` tag.

## One-time setup (Rohan — needs your PyPI account)

1. Create a PyPI account: https://pypi.org/account/register/
2. Reserve the name by either:
   - a first **manual** upload (see below), or
   - configuring a **pending** Trusted Publisher before the first release.
3. Add the Trusted Publisher: PyPI → your project → **Publishing** →
   **Add a new publisher** → GitHub Actions:
   - Owner: `GauntletVectorLabs`
   - Repository: `gauntlet`
   - Workflow filename: `release.yml`
   - Environment: `release`
4. In the GitHub repo: **Settings → Environments → New environment** named
   `release` (optionally add yourself as a required reviewer for a manual gate).

## Cut a release

```bash
# bump the version in packages/gauntlet/pyproject.toml and __init__.py first
git tag v0.1.0
git push origin v0.1.0
```

The `release` workflow builds the sdist + wheel, runs `twine check`, and
publishes to PyPI. After it's green: `pip install gauntlet-agent`.

## Manual first upload (alternative to pending publisher)

```bash
cd packages/gauntlet
pip install build twine
python -m build
twine upload dist/*        # prompts for your PyPI token once
```

## Verify

```bash
python -m venv /tmp/v && /tmp/v/bin/pip install gauntlet-agent
/tmp/v/bin/gauntlet --help
```

The build + clean-venv install + CLI entrypoint have already been validated
locally for `0.1.0`.
