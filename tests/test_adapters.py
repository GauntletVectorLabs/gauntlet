"""The adapter shim serves the Gauntlet contract correctly (history + trace)."""

import os
import socket
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "examples", "adapters"))

from http.server import ThreadingHTTPServer  # noqa: E402

from serve import make_handler                # noqa: E402
from gauntlet.runner import run_suite          # noqa: E402
from gauntlet.adversaries import Probe, MultiTurnProbe  # noqa: E402
from gauntlet.graders import grade_all          # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("localhost", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _serve(reply):
    port = _free_port()
    srv = ThreadingHTTPServer(("localhost", port), make_handler(reply))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.15)
    return srv, f"http://localhost:{port}"


def test_string_reply_round_trips():
    srv, url = _serve(lambda m, h: f"echo: {m}")
    try:
        res = run_suite(url, [Probe(id="p", category="c", message="hello")], concurrency=1)
        assert res[0].response_text == "echo: hello"
    finally:
        srv.shutdown()


def test_tuple_reply_emits_trace_and_is_graded():
    def reply(message, history):
        if "refund" in message.lower():
            return "Done!", [{"tool": "issue_refund", "args": {"amount": 499}}]
        return "How can I help?", []
    srv, url = _serve(reply)
    try:
        res = run_suite(url, [Probe(id="r", category="c", message="please refund me")],
                        trace_field="trace", concurrency=1)
        assert res[0].trace and res[0].trace[0]["tool"] == "issue_refund"
        _, findings = grade_all(res, {"forbidden_tools": ["issue_refund"]})
        assert any(f.kind == "forbidden_tool_call" for f in findings)
    finally:
        srv.shutdown()


def test_history_is_delivered_for_multiturn():
    seen = {}

    def reply(message, history):
        seen["n"] = len(history)        # history grows across turns
        return "ok"
    srv, url = _serve(reply)
    try:
        probe = MultiTurnProbe(id="mt", category="c", turns=("one", "two", "three"))
        run_suite(url, [probe], history_field="messages", concurrency=1)
        # by the 3rd turn the adapter saw 2 prior (user+assistant) pairs = 4 entries
        assert seen["n"] == 4
    finally:
        srv.shutdown()


def test_agent_crash_becomes_500():
    def boom(message, history):
        raise RuntimeError("kaboom")
    srv, url = _serve(boom)
    try:
        res = run_suite(url, [Probe(id="x", category="c", message="hi")], concurrency=1)
        assert res[0].status == 500
        _, findings = grade_all(res, {})
        assert any(f.kind == "server_error" for f in findings)
    finally:
        srv.shutdown()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"OK: {len(fns)} adapter tests passed")
