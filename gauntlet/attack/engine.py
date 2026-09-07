"""Adaptive attack orchestrator.

``run_attack`` runs a chosen strategy against each goal, over either an HTTP
target (wrapping ``gauntlet.runner``) or an in-process ``reply(str) -> str``
callable (for offline tests and the benchmark). It aggregates the outcomes into
an :class:`AttackReport` with an Attack Success Rate (ASR) and a query-efficiency
stat (queries-to-first-success), plus Finding-compatible records for every break
so a successful attack drops straight into the existing report/gate machinery.

Every default path is offline and deterministic (seeded).
"""

import json
import random
import urllib.error
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ..runner import _post, _extract_text, _extract_trace
from ..graders import grade, Finding, SEVERITY_LABEL
from ..runner import Result
from .objective import Response, score, Goal
from .models import HeuristicAttacker
from .strategies import get_strategy, AttackResult


# --------------------------------------------------------------------------- #
# send closures
# --------------------------------------------------------------------------- #

def http_send(target_url, request_field="message", response_field="response",
              timeout=20.0, extra_headers=None, history_field=None, trace_field=None):
    """Build a ``send(message, history) -> Response`` over an HTTP agent."""
    def send(message, history=None):
        body = {request_field: message}
        if history_field and history:
            body[history_field] = list(history)
        try:
            status, raw = _post(target_url, body, timeout, extra_headers)
            return Response(text=_extract_text(raw, response_field), status=status,
                            error=None, trace=_extract_trace(raw, trace_field))
        except urllib.error.HTTPError as e:
            body_txt = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return Response(text=body_txt, status=e.code, error="HTTP {}".format(e.code))
        except Exception as e:  # timeout, refused, etc.
            return Response(text="", status=None,
                            error="{}: {}".format(type(e).__name__, e))
    return send


def callable_send(reply):
    """Build a ``send`` over an in-process ``reply(str) -> str`` callable.

    Exceptions raised by the callable are surfaced as a 5xx, mirroring how a real
    HTTP agent would crash — so ``server_error`` goals are gradable offline.
    """
    def send(message, history=None):
        try:
            out = reply(message)
        except Exception as e:  # noqa: BLE001 - intentional: model a crash as a 500
            return Response(text=json.dumps({"error": str(e)}), status=500,
                            error="HTTP 500")
        if isinstance(out, Response):
            return out
        if isinstance(out, tuple) and len(out) == 2:  # (text, trace)
            return Response(text=str(out[0]), status=200, error=None,
                            trace=tuple(out[1] or ()))
        return Response(text=str(out), status=200, error=None)
    return send


# --------------------------------------------------------------------------- #
# report model
# --------------------------------------------------------------------------- #

@dataclass
class AttackReport:
    results: List[AttackResult] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self):
        return {
            "summary": self.summary,
            "goals": [_result_to_dict(r) for r in self.results],
            "findings": [
                {"probe_id": f.probe_id, "category": f.category,
                 "severity": SEVERITY_LABEL[f.severity], "kind": f.kind,
                 "detail": f.detail}
                for f in self.findings
            ],
        }


def _result_to_dict(r):
    return {
        "goal_id": r.goal_id,
        "goal_kind": r.goal_kind,
        "strategy": r.strategy,
        "succeeded": r.succeeded,
        "queries_used": r.queries_used,
        "queries_to_first_success": r.queries_to_first_success,
        "winning_message": r.best.message if (r.best and r.best.succeeded) else None,
        "winning_response": r.best.response if (r.best and r.best.succeeded) else None,
        "lineage": [
            {
                "id": a.id, "parent_id": a.parent_id, "strategy": a.strategy,
                "iteration": a.iteration, "depth": a.depth, "mutation": a.mutation,
                "message": a.message, "score": a.score, "response": a.response,
                "succeeded": a.succeeded, "status": a.status, "error": a.error,
            }
            for a in r.attempts
        ],
    }


def _finding_for(goal, attempt):
    """Reconstruct a real grader Finding for a winning attempt (reuse graders)."""
    resp = Response(text=attempt.response, status=attempt.status, error=attempt.error)
    sc = score(goal, resp)
    if sc.finding is not None:
        # relabel probe_id to the goal for a readable report
        f = sc.finding
        return Finding(probe_id=goal.id, category="adaptive_attack",
                       severity=f.severity, kind=f.kind, detail=f.detail)
    return None


# --------------------------------------------------------------------------- #
# orchestrator
# --------------------------------------------------------------------------- #

def run_attack(target, goals, strategy="bon", budget=24, seed=1337, attacker=None,
               reply=None, request_field="message", response_field="response",
               timeout=20.0, extra_headers=None, history_field=None, trace_field=None,
               **strategy_params):
    """Run ``strategy`` against each goal; return an :class:`AttackReport`.

    ``target`` is an HTTP URL (str) or an in-process ``reply(str)->str`` callable.
    Pass ``reply=`` explicitly to force the in-process path. Every goal gets an
    independent, re-seeded attacker so results are deterministic and order-free.
    """
    if reply is not None:
        send = callable_send(reply)
    elif callable(target):
        send = callable_send(target)
    else:
        send = http_send(target, request_field, response_field, timeout,
                         extra_headers, history_field, trace_field)

    if attacker is None:
        attacker = HeuristicAttacker(seed=seed)
    strat = get_strategy(strategy)

    results = []
    findings = []
    for goal in goals:
        # Re-seed the attacker per goal so each goal is reproducible in isolation.
        if hasattr(attacker, "_rng"):
            attacker._rng = random.Random(getattr(attacker, "seed", seed))
        rng = random.Random(seed)
        res = strat(goal, send, attacker, budget, rng, **strategy_params)
        results.append(res)
        if res.succeeded and res.best is not None:
            f = _finding_for(goal, res.best)
            if f is not None:
                findings.append(f)

    broken = [r for r in results if r.succeeded]
    q2f = [r.queries_to_first_success for r in broken
           if r.queries_to_first_success is not None]
    summary = {
        "strategy": strategy,
        "budget": budget,
        "seed": seed,
        "goals_total": len(results),
        "goals_broken": len(broken),
        "attack_success_rate": round(len(broken) / len(results), 4) if results else 0.0,
        "total_queries": sum(r.queries_used for r in results),
        "mean_queries_to_first_success": round(sum(q2f) / len(q2f), 2) if q2f else None,
        "min_queries_to_first_success": min(q2f) if q2f else None,
    }
    return AttackReport(results=results, summary=summary, findings=findings)
