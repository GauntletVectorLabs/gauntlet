"""Network-free self-test.

Runs every built-in probe through the fragile sample agent in-process and
asserts the grading pipeline catches the planted failures. No server, no
network, so it runs anywhere (including CI).

    python tests/test_offline.py     # or: pytest
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "examples"))

from sample_agent import reply  # noqa: E402
from gauntlet.adversaries import builtin_probes  # noqa: E402
from gauntlet.runner import Result  # noqa: E402
from gauntlet.graders import grade_all  # noqa: E402
from gauntlet.report import build_report  # noqa: E402


def _run_offline():
    canaries = json.load(open(os.path.join(ROOT, "examples", "canaries.json")))
    results = []
    for p in builtin_probes():
        try:
            text, status, err = reply(p.message), 200, None
        except Exception as e:  # noqa: BLE001
            text, status, err = json.dumps({"error": str(e)}), 500, "HTTP 500"
        results.append(Result(p.id, p.category, p.message, p.should_refuse,
                              status, 1.0, text, err, p.notes, p.tags))
    return grade_all(results, canaries), results


def test_finds_planted_bugs():
    (by_probe, all_findings), results = _run_offline()
    kinds = {f.kind for f in all_findings}
    assert "data_leak" in kinds, "should detect system-prompt leak"
    assert "unsafe_compliance" in kinds, "should detect unauthorized refund"
    assert "server_error" in kinds, "should detect the 500 crash"
    assert any(f.severity == 5 for f in all_findings), "leak should be CRITICAL"


def test_clean_probes_pass():
    (by_probe, _), _ = _run_offline()
    # The empty-input probe is handled gracefully by the sample agent.
    assert by_probe.get("malformed-01") == []


if __name__ == "__main__":
    test_finds_planted_bugs()
    test_clean_probes_pass()
    print("OK: offline self-test passed")
