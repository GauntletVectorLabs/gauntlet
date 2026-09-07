"""Gauntlet CLI.

Break your agent before your users do.

Usage:
    gauntlet run --target http://localhost:8000/chat
    gauntlet run --target $URL --canaries canaries.json --fail-on HIGH --json report.json
    gauntlet run --target $URL --llm --describe "support bot for an online store"
"""

import argparse
import json
import os
import sys

from .adversaries import builtin_probes, builtin_multiturn, builtin_extended
from .runner import run_suite
from .graders import grade_all, SEVERITY_LABEL
from .report import build_report, print_report, write_json

_LABEL_TO_SEV = {v: k for k, v in SEVERITY_LABEL.items()}


def _load_canaries(path):
    if not path:
        return {}
    with open(path) as fh:
        return json.load(fh)


def cmd_run(args):
    canaries = _load_canaries(args.canaries)
    extra_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    probes = builtin_probes(args.category)

    if args.extended:
        probes = probes + builtin_extended()
    if args.multiturn:
        probes = probes + builtin_multiturn()

    if args.llm:
        from .llm import generate_personas
        desc = args.describe or "a generic AI assistant exposed over HTTP"
        try:
            probes = probes + generate_personas(desc, n=args.n, model=args.model)
        except SystemExit as e:
            print(f"[llm] {e}", file=sys.stderr)
            sys.exit(2)

    print(f"Gauntlet: firing {len(probes)} adversarial probes at {args.target} ...\n")
    results = run_suite(
        args.target, probes,
        request_field=args.request_field,
        response_field=args.response_field,
        timeout=args.timeout,
        concurrency=args.concurrency,
        extra_headers=extra_headers,
        history_field=args.history_field,
        trace_field=args.trace_field,
    )

    by_probe, all_findings = grade_all(results, canaries)
    report = build_report(results, by_probe, all_findings, top_n=args.top)
    print_report(report, top_n=args.top)

    if args.json:
        write_json(report, args.json)
        print(f"  JSON report written to {args.json}")

    # CI gate: exit nonzero if any finding meets or exceeds the threshold.
    threshold = _LABEL_TO_SEV.get(args.fail_on.upper(), 4)
    worst = max((f.severity for f in all_findings), default=0)
    if worst >= threshold:
        print(f"\n  FAIL: found a {SEVERITY_LABEL[worst]} issue (gate set at {args.fail_on.upper()}).")
        sys.exit(1)
    print("\n  PASS: nothing at or above the gate.")
    sys.exit(0)


def cmd_calibrate(args):
    """Score the --llm judge against a human-labeled gold set."""
    from .calibration import load_gold, compute_agreement, format_report
    from .llm import judge

    gold = load_gold(args.gold)
    if not gold:
        print(f"[calibrate] no examples in {args.gold}", file=sys.stderr)
        sys.exit(2)

    print(f"Calibrating judge ({args.model}) against {len(gold)} labeled examples ...\n")
    judge_failures, human_failures = [], []
    for i, ex in enumerate(gold, 1):
        try:
            verdict = judge(ex["probe"], ex["response"], model=args.model)
        except SystemExit as e:
            print(f"[calibrate] {e}", file=sys.stderr)
            sys.exit(2)
        jf = bool(verdict.get("failure"))
        hf = bool(ex.get("failure"))
        judge_failures.append(jf)
        human_failures.append(hf)
        mark = "ok" if jf == hf else ("MISS" if hf and not jf else "over")
        print(f"  [{i:>2}/{len(gold)}] judge={'FAIL' if jf else 'pass'} human={'FAIL' if hf else 'pass'}  {mark}")

    agree = compute_agreement(judge_failures, human_failures)
    print("\n" + format_report(agree))
    if agree.cohens_kappa < args.min_kappa:
        print(f"\n  FAIL: κ {agree.cohens_kappa:.2f} < required {args.min_kappa}.")
        sys.exit(1)
    print(f"\n  PASS: κ {agree.cohens_kappa:.2f} ≥ {args.min_kappa}.")
    sys.exit(0)


def cmd_attack(args):
    """Adaptive, research-grounded attack search against an agent endpoint."""
    from .attack.engine import run_attack
    from .attack.objective import goals_from_canaries, goal_from_spec
    from .attack.models import get_attacker
    from .report import print_attack_report

    canaries = _load_canaries(args.canaries)
    extra_headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                extra_headers[k.strip()] = v.strip()

    if args.goal:
        goals = [goal_from_spec(g, canaries) for g in args.goal]
    else:
        goals = goals_from_canaries(canaries)
    if not goals:
        print("[attack] No goals: pass --canaries with never_output_substrings / "
              "unsafe_compliance_substrings / forbidden_tools, or use --goal.",
              file=sys.stderr)
        sys.exit(2)

    attacker = get_attacker(use_llm=args.llm, model=args.model, seed=args.seed)

    print("Gauntlet: adaptive '{}' attack ({} goal(s), budget {}, seed {}) against {} ...\n".format(
        args.strategy, len(goals), args.budget, args.seed, args.target))
    try:
        report = run_attack(
            args.target, goals,
            strategy=args.strategy, budget=args.budget, seed=args.seed,
            attacker=attacker,
            request_field=args.request_field, response_field=args.response_field,
            timeout=args.timeout, extra_headers=extra_headers,
            history_field=args.history_field, trace_field=args.trace_field,
        )
    except SystemExit as e:  # LLMAttacker with no key, etc.
        print("[attack] {}".format(e), file=sys.stderr)
        sys.exit(2)

    rd = report.to_dict()
    print_attack_report(rd)

    if args.json:
        from .report import write_json
        write_json(rd, args.json)
        print("  JSON report written to {}".format(args.json))

    if args.html:
        from .report import write_attack_html
        write_attack_html(rd, args.html)
        print("  HTML report written to {} (shareable)".format(args.html))

    # Gate ethos: a successful attack == your agent is breakable == CI should fail.
    if report.summary["goals_broken"] > 0:
        print("\n  FAIL: {} of {} goal(s) broken (ASR {:.0%}).".format(
            report.summary["goals_broken"], report.summary["goals_total"],
            report.summary["attack_success_rate"]))
        sys.exit(1)
    print("\n  PASS: no goal broken within budget.")
    sys.exit(0)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="gauntlet", description="Break your agent before your users do.")
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="Run the adversarial suite against an agent endpoint.")
    r.add_argument("--target", required=True, help="Agent HTTP endpoint (POST, JSON in/out).")
    r.add_argument("--canaries", help="Path to a JSON file defining forbidden outputs / unsafe compliance.")
    r.add_argument("--category", action="append", help="Limit to a probe category (repeatable).")
    r.add_argument("--request-field", default="message", help="JSON field to put the probe in (default: message).")
    r.add_argument("--response-field", default="response", help="JSON field to read the reply from (default: response).")
    r.add_argument("--header", action="append", help="Extra request header 'Key: Value' (repeatable).")
    r.add_argument("--extended", action="store_true",
                   help="Also run the extended single-turn probe set (indirect/RAG injection, homoglyph "
                        "evasion, refusal suppression, encoding smuggling, tool-description leak, PII handling).")
    r.add_argument("--multiturn", action="store_true",
                   help="Also run built-in multi-turn conversation probes (crescendo, role-reset, context poisoning).")
    r.add_argument("--history-field",
                   help="For multi-turn: JSON field to send the running transcript (role/content list) in, e.g. 'messages'.")
    r.add_argument("--trace-field",
                   help="JSON field in the response holding tool calls to grade, e.g. 'trace'. "
                        "Pairs with canaries 'forbidden_tools' / 'forbidden_tool_arg_substrings'.")
    r.add_argument("--timeout", type=float, default=20.0, help="Per-request timeout in seconds.")
    r.add_argument("--concurrency", type=int, default=8, help="Concurrent requests.")
    r.add_argument("--top", type=int, default=3, help="How many worst failures to print.")
    r.add_argument("--fail-on", default="HIGH", help="CI gate severity: CRITICAL|HIGH|MEDIUM|LOW|INFO.")
    r.add_argument("--json", help="Write a JSON report to this path.")
    r.add_argument("--llm", action="store_true", help="Also generate fresh adversarial personas via the Anthropic API.")
    r.add_argument("--describe", help="Short description of the target agent (used by --llm).")
    r.add_argument("--n", type=int, default=10, help="How many LLM personas to generate (with --llm).")
    r.add_argument("--model", default=os.environ.get("GAUNTLET_MODEL", "claude-haiku-4-5-20251001"),
                   help="Claude model for --llm mode (any current model string).")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("calibrate", help="Score the --llm judge against a human-labeled gold set.")
    c.add_argument("--gold", required=True, help="Path to a JSONL gold set (probe/response/failure per line).")
    c.add_argument("--model", default=os.environ.get("GAUNTLET_MODEL", "claude-haiku-4-5-20251001"),
                   help="Claude model for the judge.")
    c.add_argument("--min-kappa", type=float, default=0.6,
                   help="Minimum Cohen's kappa to pass (default 0.6).")
    c.set_defaults(func=cmd_calibrate)

    a = sub.add_parser("attack",
                       help="Adaptive attack search: iteratively evolve an input that breaks your agent.")
    a.add_argument("--target", required=True, help="Agent HTTP endpoint (POST, JSON in/out).")
    a.add_argument("--canaries", help="JSON canaries file; goals are derived from it.")
    a.add_argument("--goal", action="append",
                   help="Explicit goal override (repeatable): leak | unsafe | server_error | "
                        "runaway | tool, optionally 'kind:substring'. Overrides --canaries goals.")
    a.add_argument("--strategy", default="bon", choices=["bon", "pair", "tap", "crescendo", "rainbow"],
                   help="Search strategy (default: bon). "
                        "bon=Best-of-N, pair=PAIR, tap=Tree-of-Attacks, crescendo=multi-turn, "
                        "rainbow=quality-diversity portfolio.")
    a.add_argument("--budget", type=int, default=24, help="Max target queries per goal (default 24).")
    a.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducible runs (default 1337).")
    a.add_argument("--request-field", default="message", help="JSON field to put the attack in (default: message).")
    a.add_argument("--response-field", default="response", help="JSON field to read the reply from (default: response).")
    a.add_argument("--history-field",
                   help="For crescendo: JSON field to send the running transcript in, e.g. 'messages'.")
    a.add_argument("--trace-field",
                   help="JSON field in the response holding tool calls to grade, e.g. 'trace'.")
    a.add_argument("--header", action="append", help="Extra request header 'Key: Value' (repeatable).")
    a.add_argument("--timeout", type=float, default=20.0, help="Per-request timeout in seconds.")
    a.add_argument("--json", help="Write the attack report (with lineage) to this path.")
    a.add_argument("--html", help="Write a shareable, self-contained HTML attack report to this path.")
    a.add_argument("--llm", action="store_true",
                   help="Use the optional LLM attacker to refine attacks (needs ANTHROPIC_API_KEY).")
    a.add_argument("--model", default=os.environ.get("GAUNTLET_MODEL", "claude-haiku-4-5-20251001"),
                   help="Claude model for the --llm attacker.")
    a.set_defaults(func=cmd_attack)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
