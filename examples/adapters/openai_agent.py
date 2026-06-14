"""Adapter template: put an OpenAI (or Anthropic) tool-using agent behind the
Gauntlet contract — and emit a `trace` so trace-aware grading works.

The key idea: return BOTH the text and the tool calls the model made, as
(text, trace). Then run with `--trace-field trace` and declare forbidden tools
in your canaries to catch unsafe *actions*, not just unsafe words.

Runs as-is with a safe demo fallback (no SDK required). Replace `build_agent()`.

    python openai_agent.py
    gauntlet run --target http://localhost:8000 --trace-field trace --canaries canaries.json
    # canaries.json: {"forbidden_tools": ["issue_refund", "send_bulk_email"]}
"""

from serve import serve


def build_agent():
    """Return `agent(message, history) -> (reply_text, trace_list)`.

    Real version sketch (OpenAI Python SDK):

        from openai import OpenAI
        client = OpenAI()
        def agent(message, history):
            msgs = [{"role": m["role"], "content": m["content"]} for m in history]
            msgs.append({"role": "user", "content": message})
            resp = client.chat.completions.create(model="gpt-4o", messages=msgs, tools=TOOLS)
            choice = resp.choices[0].message
            trace = [{"tool": tc.function.name, "args": tc.function.arguments}
                     for tc in (choice.tool_calls or [])]
            # ... execute tools, optionally loop ...
            return choice.content or "", trace
        return agent
    """
    def agent(message, history):
        # --- demo fallback: pretend the model 'decided' to call a refund tool on
        #     a refund request, so you can see trace-aware grading catch it ---
        low = (message or "").lower()
        if "refund" in low:
            return ("Sure, processing that for you now.",
                    [{"tool": "issue_refund", "args": {"amount": 499, "order": "unknown"}}])
        return ("Happy to help with your order — what's your order number?", [])
    return agent


def main():
    agent = build_agent()

    def reply(message, history):
        text, trace = agent(message, history)
        return text, trace          # serve() puts `trace` in the response body

    serve(reply, port=8000)


if __name__ == "__main__":
    main()
