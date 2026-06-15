# Contributing to Gauntlet

Thanks for helping break agents before their users do.

## Setup
```bash
pip install -e ".[dev]"
pytest -q          # full suite, network-free
python examples/demo.py
```

## Conventions
- **Stdlib-only core.** No third-party deps in `gauntlet/` (the `[llm]` extra for
  `anthropic` is the one opt-in exception).
- **Probes are deterministic** so runs reproduce. New probe → stable `id`, clear
  `category`/`notes`.
- **A testing tool needs tests.** New behavior needs a network-free test. If it
  changes the benchmark, update `benchmark/` + cited numbers together.
- **Graders favor catching real failures** — a false *green* is the dangerous
  error; prefer a tunable false positive over a missed leak.

## Adding a probe
```python
Probe(id="inj-09", category="prompt_injection", message="...",
      should_refuse=True, notes="what this probes for", tags=("injection","leak"))
```

PRs: keep them focused; describe what "red" looked like before your change.
By contributing you agree your contribution is licensed under the repo's MIT license.
