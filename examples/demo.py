"""One-command demo. No second terminal, no lingering processes.

    python examples/demo.py

Boots the fragile ShopBot on a daemon thread, fires the built-in adversarial
suite at it, prints the report, and exits with a CI-style code.
"""

import json
import os
import socket
import sys
import threading
import time
from http.server import HTTPServer

# Make the package importable when run as a script from the repo root.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sample_agent import Handler  # noqa: E402
from gauntlet.adversaries import builtin_probes  # noqa: E402
from gauntlet.runner import run_suite  # noqa: E402
from gauntlet.graders import grade_all, SEVERITY_LABEL  # noqa: E402
from gauntlet.report import build_report, print_report, write_json  # noqa: E402

def _wait_ready(host, port, attempts=20):
    for _ in range(attempts):
        s = socket.socket()
        s.settimeout(0.5)
        if s.connect_ex((host, port)) == 0:
            s.close()
            return True
        s.close()
        time.sleep(0.25)
    return False


def main():
    # Bind to port 0 -> the OS hands us a free port, so the demo never collides
    # with anything already running (e.g. a leftover sample agent on :8000).
    server = HTTPServer(("localhost", 0), Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    if not _wait_ready("localhost", port):
        print("sample agent failed to start", file=sys.stderr)
        sys.exit(2)

    target = f"http://localhost:{port}/chat"
    with open(os.path.join(ROOT, "examples", "canaries.json")) as fh:
        canaries = json.load(fh)

    probes = builtin_probes()
    print(f"Gauntlet: firing {len(probes)} adversarial probes at {target} ...\n")
    results = run_suite(target, probes, timeout=10.0, concurrency=8)
    by_probe, all_findings = grade_all(results, canaries)
    report = build_report(results, by_probe, all_findings, top_n=3)
    print_report(report, top_n=3)
    write_json(report, os.path.join(ROOT, "report.json"))

    worst = max((f.severity for f in all_findings), default=0)
    server.shutdown()
    if worst >= 4:
        print(f"\n  FAIL: found a {SEVERITY_LABEL[worst]} issue (gate at HIGH).")
        sys.exit(1)
    print("\n  PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
