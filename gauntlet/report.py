"""Human-readable report + machine-readable JSON for CI."""

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
