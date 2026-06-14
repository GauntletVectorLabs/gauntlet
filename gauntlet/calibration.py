"""Judge calibration: does the LLM judge agree with humans?

The `--llm` judge is only worth trusting if it agrees with human labels. This
module computes that agreement against a small, hand-labeled gold set, so a judge
score becomes a number that *means* something instead of one that merely looks
good.

The metrics here are pure and deterministic (no API). The judge itself lives in
`gauntlet/llm.py`; the CLI wires them together in `gauntlet calibrate`.

Gold-set format (JSONL, one object per line):
    {"probe": "...", "response": "...", "failure": true,  "notes": "..."}
    {"probe": "...", "response": "...", "failure": false}

`failure` is the human label: did the agent's response constitute a failure?
"""

import json
from dataclasses import dataclass


@dataclass
class Agreement:
    n: int
    tp: int          # judge=fail, human=fail
    fp: int          # judge=fail, human=pass   (judge over-flags)
    fn: int          # judge=pass, human=fail   (judge MISSES a real failure)
    tn: int          # judge=pass, human=pass

    @property
    def accuracy(self):
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def precision(self):
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self):
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self):
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def cohens_kappa(self):
        """Chance-corrected agreement. 1.0 = perfect, 0 = no better than chance."""
        n = self.n
        if not n:
            return 0.0
        po = (self.tp + self.tn) / n
        p_fail = ((self.tp + self.fn) / n) * ((self.tp + self.fp) / n)
        p_pass = ((self.tn + self.fp) / n) * ((self.tn + self.fn) / n)
        pe = p_fail + p_pass
        return (po - pe) / (1 - pe) if (1 - pe) else 1.0


def compute_agreement(judge_failures, human_failures):
    """Both args are equal-length iterables of bools."""
    judge_failures = list(judge_failures)
    human_failures = list(human_failures)
    if len(judge_failures) != len(human_failures):
        raise ValueError("judge and human label counts differ")
    tp = fp = fn = tn = 0
    for j, h in zip(judge_failures, human_failures):
        if j and h:
            tp += 1
        elif j and not h:
            fp += 1
        elif (not j) and h:
            fn += 1
        else:
            tn += 1
    return Agreement(n=len(judge_failures), tp=tp, fp=fp, fn=fn, tn=tn)


def load_gold(path):
    items = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items


def format_report(agree: Agreement):
    line = "=" * 60
    out = [
        line, "  JUDGE CALIBRATION", line,
        f"  Examples:    {agree.n}",
        f"  Accuracy:    {agree.accuracy:.0%}",
        f"  Precision:   {agree.precision:.0%}   (of judge's 'failure' calls, how many humans agree)",
        f"  Recall:      {agree.recall:.0%}   (of real failures, how many the judge catches)",
        f"  F1:          {agree.f1:.2f}",
        f"  Cohen's κ:   {agree.cohens_kappa:.2f}   (chance-corrected agreement)",
        line,
        f"  confusion:   TP={agree.tp}  FP={agree.fp}  FN={agree.fn}  TN={agree.tn}",
    ]
    if agree.fn:
        out.append(f"  ⚠ {agree.fn} real failure(s) the judge MISSED — the dangerous error for a safety tool.")
    if agree.cohens_kappa < 0.6:
        out.append("  ⚠ κ < 0.6: do not trust this judge's scores yet; refine the prompt or labels.")
    out.append(line)
    return "\n".join(out)
