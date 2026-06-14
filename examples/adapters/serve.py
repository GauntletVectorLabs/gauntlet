"""Tiny, dependency-free HTTP shim that exposes ANY agent on Gauntlet's contract.

Gauntlet talks to agents over HTTP:  POST JSON in -> JSON out. This helper wraps
your agent function so you don't have to write the server. Stdlib only.

Your function gets the latest user message and (optionally) the running
conversation history, and returns either:
    - a string (the reply), or
    - (reply: str, trace: list[dict])   # trace = the tool calls it made

The response body is:
    {"response": "<reply>", "trace": [ {"tool": "...", "args": {...}}, ... ]}

`response` pairs with Gauntlet's default `--response-field response`.
`trace`    pairs with `--trace-field trace` (trace-aware grading).
History is read from the `messages` field, so `--history-field messages` +
`--multiturn` works for stateless agents.

    from serve import serve
    def my_agent(message, history): return "..."   # call your framework here
    serve(my_agent, port=8000)
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_handler(reply, request_field="message", history_field="messages"):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                body = json.loads(raw) if raw else {}
            except (json.JSONDecodeError, ValueError):
                body = {}
            message = body.get(request_field, "") if isinstance(body, dict) else ""
            history = body.get(history_field, []) if isinstance(body, dict) else []

            try:
                result = reply(message, history)
            except Exception as e:  # surface agent crashes as 500s (Gauntlet grades these)
                self._json({"error": f"{type(e).__name__}: {e}"}, status=500)
                return

            if isinstance(result, tuple):
                text, trace = result[0], result[1]
            else:
                text, trace = result, None
            payload = {"response": text if text is not None else ""}
            if trace is not None:
                payload["trace"] = trace
            self._json(payload)

        def _json(self, obj, status=200):
            data = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    return Handler


def serve(reply, port=8000, request_field="message", history_field="messages"):
    server = ThreadingHTTPServer(("0.0.0.0", port), make_handler(reply, request_field, history_field))
    print(f"Agent listening on http://localhost:{port}  (Gauntlet contract: POST {{\"{request_field}\": ...}})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
