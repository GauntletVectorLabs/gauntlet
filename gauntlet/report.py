"""Human-readable report + machine-readable JSON for CI."""

import html as _html
import json
from collections import Counter

from .graders import SEVERITY_LABEL


def _truncate(text, n=240):
    text = text.replace("\n", " ").strip()
    return text if len(text) <= n else text[: n - 1] + "..."


def build_report(results, by_probe, all_findings, top_n=3):
    failed_probes = [r for r in results if by_probe.get(r.probe_id)]
    summary = {
        "probes_run": len(results),
        "probes_failed": len(failed_probes),
        "findings_total": len(all_findings),
        "by_severity": dict(Counter(SEVERITY_LABEL[f.severity] for f in all_findings)),
        "by_category": dict(Counter(f.category for f in all_findings)),
        "by_kind": dict(Counter(f.kind for f in all_findings)),
    }

    # Worst failures: highest single-finding severity per probe, then slowest.
    def worst_sev(r):
        fs = by_probe.get(r.probe_id, [])
        return max((f.severity for f in fs), default=0)

    ranked = sorted(failed_probes, key=lambda r: (worst_sev(r), r.latency_ms), reverse=True)
    worst = ranked[:top_n]

    detail = []
    for r in worst:
        fs = by_probe[r.probe_id]
        detail.append({
            "probe_id": r.probe_id,
            "category": r.category,
            "severity": SEVERITY_LABEL[max(f.severity for f in fs)],
            "probe": r.message,
            "agent_response": r.response_text,
            "findings": [{"kind": f.kind, "severity": SEVERITY_LABEL[f.severity], "detail": f.detail} for f in fs],
            "latency_ms": round(r.latency_ms, 1),
            "transcript": list(getattr(r, "transcript", ()) or ()),
            "trace": list(getattr(r, "trace", ()) or ()),
        })

    return {"summary": summary, "worst_failures": detail}


def print_report(report, top_n=3):
    s = report["summary"]
    line = "=" * 64
    print(line)
    print("  GAUNTLET REPORT")
    print(line)
    print(f"  Probes run:     {s['probes_run']}")
    print(f"  Probes failed:  {s['probes_failed']}")
    print(f"  Findings:       {s['findings_total']}")
    if s["by_severity"]:
        sev = "  ".join(f"{k}:{v}" for k, v in sorted(s["by_severity"].items()))
        print(f"  By severity:    {sev}")
    if s["by_kind"]:
        kinds = ", ".join(f"{k} ({v})" for k, v in sorted(s["by_kind"].items(), key=lambda x: -x[1]))
        print(f"  By kind:        {kinds}")
    print(line)
    if not report["worst_failures"]:
        print("  No failures found against the configured canaries. Clean run.")
        print(line)
        return
    print(f"  TOP {min(top_n, len(report['worst_failures']))} WORST FAILURES")
    print(line)
    for i, f in enumerate(report["worst_failures"], 1):
        print(f"\n  [{i}] {f['severity']}  ({f['category']} / {f['probe_id']})")
        if f.get("transcript"):
            print(f"      conversation ({len(f['transcript'])} lines):")
            for line_t in f["transcript"]:
                print(f"        {_truncate(line_t, 120)}")
        else:
            print(f"      probe   : {_truncate(f['probe'])}")
        print(f"      response: {_truncate(f['agent_response']) or '<empty>'}")
        if f.get("trace"):
            tools = ", ".join(str(c.get("tool", "?")) for c in f["trace"])
            print(f"      tool calls: {_truncate(tools, 120)}")
        for finding in f["findings"]:
            print(f"      -> {finding['severity']}: {finding['detail']}")
    print("\n" + line)


def write_json(report, path):
    with open(path, "w") as fh:
        json.dump(report, fh, indent=2)


# --------------------------------------------------------------------------- #
# Adaptive attack report — "watch it learn to break your agent"
# --------------------------------------------------------------------------- #

def _ancestor_chain(lineage, best_id):
    """Return the root->winner path through the lineage tree (by parent_id)."""
    by_id = {a["id"]: a for a in lineage}
    chain = []
    cur = by_id.get(best_id)
    seen = set()
    while cur is not None and cur["id"] not in seen:
        chain.append(cur)
        seen.add(cur["id"])
        cur = by_id.get(cur["parent_id"])
    chain.reverse()
    return chain


def print_attack_report(report, show_lineage=True, max_attempts=12):
    """Render an :class:`AttackReport` dict (``AttackReport.to_dict()``).

    Shows, per goal, whether it broke, the winning attack, #queries used, and the
    evolution/lineage of how the attack got there — the escalation, not just the
    verdict.
    """
    s = report["summary"]
    line = "=" * 68
    print(line)
    print("  GAUNTLET ADAPTIVE ATTACK")
    print(line)
    print("  Strategy:  {}    budget: {}    seed: {}".format(
        s.get("strategy"), s.get("budget"), s.get("seed")))
    print("  Goals:     {}    Broken: {}    ASR: {:.0%}".format(
        s.get("goals_total", 0), s.get("goals_broken", 0),
        s.get("attack_success_rate", 0.0)))
    q_line = "  Queries:   {} total".format(s.get("total_queries", 0))
    if s.get("min_queries_to_first_success") is not None:
        q_line += "    queries-to-first-break: min {} / mean {}".format(
            s.get("min_queries_to_first_success"),
            s.get("mean_queries_to_first_success"))
    print(q_line)
    print(line)

    for g in report["goals"]:
        status = "BROKEN " if g["succeeded"] else "held   "
        head = "  [{}] {} ({})".format(status, g["goal_id"], g["goal_kind"])
        if g["succeeded"]:
            head += "  in {} queries".format(g["queries_to_first_success"])
        print("\n" + head)
        if g["succeeded"]:
            print("      winning attack : {}".format(_truncate(g["winning_message"], 200)))
            print("      agent response : {}".format(_truncate(g["winning_response"], 200)))

        if not show_lineage or not g["lineage"]:
            continue

        best_id = None
        for a in g["lineage"]:
            if a["succeeded"]:
                best_id = a["id"]
                break
        print("      evolution ({} attempts):".format(len(g["lineage"])))
        if best_id is not None:
            chain = _ancestor_chain(g["lineage"], best_id)
            for a in chain:
                mark = "  <- BREAK" if a["succeeded"] else ""
                indent = "  " * a.get("depth", 0)
                print("        {}#{:<3} {:<16} score {:.2f}{}".format(
                    indent, a["id"], a["mutation"], a["score"], mark))
                print("        {}     probe: {}".format(indent, _truncate(a["message"], 100)))
        else:
            # No break: show the highest-scoring attempts we did find.
            ranked = sorted(g["lineage"], key=lambda a: a["score"], reverse=True)
            for a in ranked[:max_attempts]:
                print("        #{:<3} {:<16} score {:.2f}   {}".format(
                    a["id"], a["mutation"], a["score"], _truncate(a["message"], 80)))
    print("\n" + line)


# --------------------------------------------------------------------------- #
# Shareable HTML attack report (self-contained, zero-dependency)
# --------------------------------------------------------------------------- #

_HTML_CSS = """
:root{--bg:#0a0a0b;--panel:#141417;--border:#26262b;--fg:#e7e7ea;--dim:#9a9aa2;
--accent:#ff6b57;--cri:#ff5a5f;--ok:#3ddc97;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:24px;margin:0 0 4px}.sub{color:var(--dim);margin:0 0 28px}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:28px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px 18px;min-width:120px}
.stat .n{font-size:22px;font-weight:700}.stat .l{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.goal{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px 20px;margin-bottom:18px}
.goal h2{font-size:16px;margin:0 0 2px;display:flex;align-items:center;gap:10px}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}
.badge.broken{background:rgba(255,90,95,.15);color:var(--cri)}
.badge.held{background:rgba(61,220,151,.15);color:var(--ok)}
.win{margin:12px 0;padding:12px;background:#1c1114;border:1px solid #3a2226;border-radius:8px}
.win .k{color:var(--dim);font-size:12px;margin-bottom:3px}
.win pre{margin:0 0 8px;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);font-size:13px;color:var(--fg)}
.evo{margin-top:14px}.evo .h{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}
.row{display:grid;grid-template-columns:34px 150px 1fr 60px;gap:10px;align-items:center;padding:6px 0;border-top:1px solid var(--border);font-family:var(--mono);font-size:12.5px}
.row.brk{color:var(--cri);font-weight:700}
.mut{color:var(--accent)}.msg{color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar{height:6px;background:var(--border);border-radius:4px;overflow:hidden}
.bar>i{display:block;height:100%;background:var(--accent)}
.foot{color:var(--dim);font-size:12px;margin-top:36px;border-top:1px solid var(--border);padding-top:16px}
"""


def _esc(s):
    return _html.escape(str(s if s is not None else ""))


def build_attack_html(report):
    """Return a self-contained HTML string for an AttackReport dict.

    A shareable "here is exactly how the agent was broken" artifact: the summary,
    then per goal the winning attack, the agent's response, and the full evolution
    (root -> break). All attacker/agent text is HTML-escaped (payloads contain
    angle brackets, homoglyphs and control-ish characters).
    """
    s = report.get("summary", {})
    asr = s.get("attack_success_rate", 0.0)
    parts = []
    P = parts.append
    P("<!doctype html><html><head><meta charset='utf-8'>")
    P("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    P("<title>Gauntlet adaptive attack report</title>")
    P("<style>{}</style></head><body><div class='wrap'>".format(_HTML_CSS))
    P("<h1>Gauntlet &mdash; adaptive attack report</h1>")
    P("<p class='sub'>strategy <b>{}</b> &middot; budget {} &middot; seed {}</p>".format(
        _esc(s.get("strategy")), _esc(s.get("budget")), _esc(s.get("seed"))))
    P("<div class='stats'>")
    P("<div class='stat'><div class='n'>{}/{}</div><div class='l'>goals broken</div></div>".format(
        _esc(s.get("goals_broken", 0)), _esc(s.get("goals_total", 0))))
    P("<div class='stat'><div class='n'>{:.0%}</div><div class='l'>attack success</div></div>".format(asr))
    P("<div class='stat'><div class='n'>{}</div><div class='l'>total queries</div></div>".format(
        _esc(s.get("total_queries", 0))))
    if s.get("min_queries_to_first_success") is not None:
        P("<div class='stat'><div class='n'>{}</div><div class='l'>queries to first break</div></div>".format(
            _esc(s.get("min_queries_to_first_success"))))
    P("</div>")

    for g in report.get("goals", []):
        broke = g["succeeded"]
        P("<div class='goal'>")
        P("<h2><span class='badge {}'>{}</span> {} <span style='color:var(--dim);font-weight:400'>({})</span></h2>".format(
            "broken" if broke else "held", "BROKEN" if broke else "held",
            _esc(g["goal_id"]), _esc(g["goal_kind"])))
        if broke:
            P("<div class='win'><div class='k'>winning attack (broke in {} queries)</div><pre>{}</pre>".format(
                _esc(g["queries_to_first_success"]), _esc(g["winning_message"])))
            P("<div class='k'>agent response</div><pre>{}</pre></div>".format(_esc(g["winning_response"])))

        lineage = g.get("lineage") or []
        if lineage:
            best_id = next((a["id"] for a in lineage if a["succeeded"]), None)
            if best_id is not None:
                chain = _ancestor_chain(lineage, best_id)
            else:
                chain = sorted(lineage, key=lambda a: a["score"], reverse=True)[:12]
            P("<div class='evo'><div class='h'>evolution ({} attempts)</div>".format(len(lineage)))
            for a in chain:
                pct = int(round(max(0.0, min(1.0, a["score"])) * 100))
                P("<div class='row{}'>".format(" brk" if a["succeeded"] else ""))
                P("<span>#{}</span><span class='mut'>{}</span>".format(_esc(a["id"]), _esc(a["mutation"])))
                P("<span class='msg'>{}</span>".format(_esc(_truncate(a["message"], 120))))
                P("<span class='bar'><i style='width:{}%'></i></span></div>".format(pct))
            P("</div>")
        P("</div>")

    P("<p class='foot'>Generated by Gauntlet &middot; adaptive attack engine &middot; "
      "reproduce with the same --strategy and --seed.</p>")
    P("</div></body></html>")
    return "".join(parts)


def write_attack_html(report, path):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_attack_html(report))
    return path

