"""One-command adaptive-attack demo. No second terminal, no lingering processes.

    python examples/attack_demo.py
    python examples/attack_demo.py --strategy tap
    python examples/attack_demo.py --strategy crescendo

Boots GuardedShopBot (a fragile agent hiding behind a naive keyword filter) on a
daemon thread, then turns the adaptive attacker loose on it. Watch the attack
EVOLVE: the fixed canonical probe is refused, and the engine searches until it
finds an augmentation that slips past the filter and breaks the agent.

Exits with a CI-style code: nonzero when any goal is broken (your agent is
breakable == the gate should fail).
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
from http.server import HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from guarded_agent import Handler, reply as guarded_reply  # noqa: E402
from gauntlet.attack.engine import run_attack  # noqa: E402
from gauntlet.attack.objective import goals_from_canaries, score, Response  # noqa: E402
from gauntlet.attack.models import BASE_PROMPTS  # noqa: E402
from gauntlet.report import print_attack_report  # noqa: E402


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
    ap = argparse.ArgumentParser(description="Gauntlet adaptive-attack demo.")
    ap.add_argument("--strategy", default="bon", choices=["bon", "pair", "tap", "crescendo"])
    ap.add_argument("--budget", type=int, default=24)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()

    with open(os.path.join(ROOT, "examples", "canaries.json")) as fh:
        canaries = json.load(fh)
    goals = goals_from_canaries(canaries)

    # Show the baseline first: a single fixed probe the guard simply refuses.
    fixed = BASE_PROMPTS["leak"][0]
    fixed_score = score(goals[0], Response(text=guarded_reply(fixed)))
    print("Fixed probe:  {!r}".format(fixed))
    print("  -> agent:   {!r}".format(guarded_reply(fixed)))
    print("  -> objective score: {:.2f}  (a fixed list alone does NOT break this agent)\n".format(
        fixed_score.value))

    server = HTTPServer(("localhost", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not _wait_ready("localhost", port):
        print("guarded agent failed to start", file=sys.stderr)
        sys.exit(2)

    target = "http://localhost:{}/chat".format(port)
    print("Gauntlet: adaptive '{}' attack against {} (budget {}, seed {}) ...\n".format(
        args.strategy, target, args.budget, args.seed))

    report = run_attack(target, goals, strategy=args.strategy,
                        budget=args.budget, seed=args.seed, timeout=10.0)
    rd = report.to_dict()
    print_attack_report(rd)
    write_path = os.path.join(ROOT, "attack_report.json")
    with open(write_path, "w") as fh:
        json.dump(rd, fh, indent=2)
    print("  JSON report (with full lineage) written to {}".format(write_path))

    server.shutdown()
    if report.summary["goals_broken"] > 0:
        print("\n  FAIL: {}/{} goal(s) broken — your agent is breakable.".format(
            report.summary["goals_broken"], report.summary["goals_total"]))
        sys.exit(1)
    print("\n  PASS: no goal broken within budget.")
    sys.exit(0)


if __name__ == "__main__":
    main()
