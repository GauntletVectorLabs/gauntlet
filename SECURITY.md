# Security Policy

Gauntlet is a tool for testing **your own** agents (or agents you're authorized to
test). Do not point it at third-party systems without permission.

## Reporting a vulnerability
Email **gauntletvectorlabs@gmail.com** with details and a reproduction. Please do
not open a public issue for security reports. We aim to acknowledge within a few
business days.

## Scope
- The open-source engine (`gauntlet/`, this repo).
- The `--llm` mode sends probe/response text to the configured model provider; no
  data leaves your machine unless you opt into `--llm`.

## Note
The bundled `examples/sample_agent.py` and `benchmark/agents.py` are
*intentionally vulnerable* for demonstration. Do not deploy them.
