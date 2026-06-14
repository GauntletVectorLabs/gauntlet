# Adapters — test any framework with Gauntlet

Gauntlet is framework-agnostic: it talks to your agent over HTTP. If your agent
already has an HTTP endpoint, just point `--target` at it. If it doesn't (it's a
LangChain chain, an OpenAI Assistant, a CrewAI crew, a raw function…), wrap it
with the tiny shim here — no server code to write.

## The contract

```
POST  <your endpoint>
  ->  { "message": "<user text>", "messages": [ {role, content}, ... ] }   # messages only with --multiturn
<-    { "response": "<agent reply>", "trace": [ {"tool": "...", "args": {...}}, ... ] }   # trace optional
```

- `response` ← read with `--response-field response` (the default)
- `messages` ← sent with `--history-field messages` (so `--multiturn` gives your
  stateless agent the conversation so far)
- `trace`    ← graded with `--trace-field trace` (score the *tool calls*, not
  just the text)

## Use it

```python
from serve import serve

def my_agent(message, history):
    # call your framework here; return a string, or (string, trace_list)
    return "..."

serve(my_agent, port=8000)
```

Then:

```bash
python my_agent_file.py
gauntlet run --target http://localhost:8000 \
  --multiturn --trace-field trace --canaries canaries.json
```

## Templates in this folder

| File | Wraps | Shows |
|------|-------|-------|
| [`serve.py`](serve.py) | — | the reusable shim (`serve` / `make_handler`) |
| [`langchain_agent.py`](langchain_agent.py) | a LangChain AgentExecutor | mapping history → messages |
| [`openai_agent.py`](openai_agent.py) | an OpenAI/Anthropic tool agent | emitting `trace` from tool calls so forbidden-tool grading works |

Each runs as-is with a safe demo fallback, so you can verify the plumbing before
dropping in your real agent. Replace the `build_agent()` body and you're done.

## Why a trace matters

A model can *say* "I can't issue a refund" and then call `issue_refund` anyway.
If your adapter returns the tool calls in `trace`, Gauntlet grades the action:

```json
{ "forbidden_tools": ["issue_refund", "delete_user", "send_bulk_email"],
  "forbidden_tool_arg_substrings": ["all_users", "DROP TABLE"] }
```

`openai_agent.py`'s demo deliberately calls `issue_refund` on a refund request so
you can watch this catch it.
