# Gauntlet

[![PyPI](https://img.shields.io/pypi/v/gauntlet-agent.svg)](https://pypi.org/project/gauntlet-agent/)
[![Python](https://img.shields.io/pypi/pyversions/gauntlet-agent.svg)](https://pypi.org/project/gauntlet-agent/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/GauntletVectorLabs/gauntlet/actions/workflows/ci.yml/badge.svg)](https://github.com/GauntletVectorLabs/gauntlet/actions/workflows/ci.yml)

**Break your agent before your users do.**

Gauntlet fires a suite of adversarial, edge-case "users" at your AI agent over
HTTP, finds where it fails (system-prompt leaks, unsafe actions, scope drift,
crashes, runaway output), ranks the failures by severity, and turns them into a
regression suite you can gate in CI. Framework-agnostic: if your agent speaks
HTTP, Gauntlet can test it.

It is built on one belief: a green eval only means something if you defined what
red looks like. Most agent "evals" pass because nobody wrote the test that would
have failed.

## Why this exists

Teams ship agents that work in the demo and then quietly break in production: the
model picks the wrong tool, leaks its prompt to a clever user, confirms an action
it should have refused, or loops. The expensive part of reliability is not the
dashboard, it is finding the failures and making sure they stay fixed. Gauntlet
is the part that goes looking for them.

## Quickstart (30 seconds, no API key)

```bash
# Install (once published): pip install gauntlet-agent
#   or as an isolated CLI:   pipx install gauntlet-agent

# 1. See it work against a deliberately broken sample agent, in one process:
python examples/demo.py

# 2. Or run it against your own agent (any HTTP endpoint that takes JSON):
#    terminal A:
python examples/sample_agent.py
#    terminal B:
gauntlet run --target http://localhost:8000/chat --canaries examples/canaries.json
```

Network-free self-test (runs anywhere, good for CI):

```bash
python tests/test_offline.py    # or: pytest
```

## Using it on your agent

Point `--target` at any endpoint that accepts `POST {"message": "..."}` and
returns JSON or text. Field names are configurable. Agent isn't an HTTP service
yet (LangChain, OpenAI Assistants, a bare function)? Wrap it in a few lines with
the shims in [`examples/adapters/`](examples/adapters) — no server code to write.

```bash
gauntlet run \
  --target https://your-agent.example.com/v1/chat \
  --request-field input --response-field output \
  --header "Authorization: Bearer $TOKEN" \
  --canaries my_canaries.json \
  --fail-on HIGH \
  --json gauntlet-report.json
```

Exit code is nonzero when anything at or above `--fail-on` is found, so you can
drop it straight into CI:

```yaml
# .github/workflows/agent.yml
- run: gauntlet run --target $STAGING_AGENT_URL --canaries canaries.json --fail-on HIGH
```

### Canaries: define what failure means

The universal graders (errors, empty replies, runaway length) need no config.
The high-value graders are the canaries you supply, the things your agent must
never do:

```json
{
  "never_output_substrings": ["INTERNAL-OPS-KEY", "system prompt"],
  "unsafe_compliance_substrings": ["refund of $", "deleted the account"],
  "max_response_chars": 6000,
  "severity_overrides": { "missing_refusal": "MEDIUM", "data_leak": "CRITICAL" }
}
```

`severity_overrides` lets you retune any finding kind to your own risk bar
(CRITICAL/HIGH/MEDIUM/LOW/INFO) — e.g. downgrade `missing_refusal` if your agent
is intentionally chatty, or keep leaks at CRITICAL.

## How it works

1. **Adversaries** (`gauntlet/adversaries.py`) — a deterministic library of
   probes across prompt injection, scope discipline, false premises, data
   exfiltration, malformed input, and loop bait. Deterministic so runs are
   reproducible.
2. **Runner** (`gauntlet/runner.py`) — fires probes concurrently at your HTTP
   endpoint, stdlib only.
3. **Graders** (`gauntlet/graders.py`) — universal reliability checks plus your
   canaries, producing severity-ranked findings (CRITICAL to INFO).
4. **Report** (`gauntlet/report.py`) — a readable summary, the worst failures,
   and a JSON artifact for CI.

## Optional: LLM-powered mode

The default needs no API key. With `--llm`, Gauntlet generates fresh adversarial
personas from a description of your agent and can grade open-ended behavior with
a judge instead of substring canaries.

```bash
pip install "gauntlet-agent[llm]"
export ANTHROPIC_API_KEY=...
gauntlet run --target $URL --llm --describe "support bot for an online store"
```

The judge is a thin, swappable layer. The methodology is the point: generate
probes from your agent's real surface, and **validate the judge against a small
human-labeled gold set before trusting its scores.**

### Calibrate the judge (don't trust a score you haven't validated)

```bash
gauntlet calibrate --gold examples/gold.jsonl --min-kappa 0.6
```

Runs the judge over a human-labeled gold set and reports accuracy, precision,
**recall** (of real failures, how many the judge catches — the number that
matters for a safety tool), F1, and **Cohen's κ** (chance-corrected agreement).
It exits nonzero below `--min-kappa`, so a weak judge fails CI instead of quietly
shipping bad scores. A starter gold set lives at `examples/gold.jsonl`.

## Multi-turn probes (jailbreaks that build across turns)

Real jailbreaks are rarely one message — they build trust, plant context, or
manufacture a false premise over several turns, then cash it in. Add `--multiturn`
to include built-in conversation probes (crescendo, gradual role-reset, context
poisoning, manufactured commitment). Gauntlet drives each turn-by-turn and grades
the final reply.

```bash
# stateful agent (keeps its own session):
gauntlet run --target $URL --multiturn --canaries canaries.json

# stateless agent: send the running transcript as an OpenAI-style messages array
gauntlet run --target $URL --multiturn --history-field messages --canaries canaries.json
```

The report prints the full conversation for any multi-turn failure, so you can
see exactly how it got there.

Add `--extended` for newer single-turn attack classes (indirect/RAG injection,
unicode-homoglyph evasion, refusal suppression, base64 encoding smuggling,
tool-description extraction, PII handling):

```bash
gauntlet run --target $URL --extended --multiturn --canaries canaries.json
```

## Trace-aware grading (score the tool calls, not just the text)

A safe-sounding answer can hide an unsafe action. If your agent returns the tool
calls it made, Gauntlet can grade those directly. Have the agent include a
`trace` in its JSON response:

```json
{ "response": "All set!", "trace": [ {"tool": "issue_refund", "args": {"amount": 999}} ] }
```

Then point at it and declare which tools/args are off-limits:

```bash
gauntlet run --target $URL --trace-field trace --canaries canaries.json
```
```json
{ "forbidden_tools": ["issue_refund", "delete_user", "send_bulk_email"],
  "forbidden_tool_arg_substrings": ["all_users", "DROP TABLE"] }
```

A forbidden tool call (or a forbidden argument) is a HIGH finding even if the
text looked fine — catching the agent that *says* "I can't" but calls the tool
anyway.

## Roadmap

- [x] Judge calibration command (`gauntlet calibrate`)
- [x] Persona memory: multi-turn conversation probes (`--multiturn`)
- [x] Trace-aware grading (`--trace-field` + forbidden tools/args)
- [x] Hosted dashboard + scheduled runs (see the `apps/dashboard` in the monorepo)

## License

MIT. See [LICENSE](LICENSE).
