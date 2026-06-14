"""Tests for judge-calibration metrics. Pure + deterministic (no API)."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from gauntlet.calibration import compute_agreement, load_gold  # noqa: E402


def test_perfect_agreement():
    a = compute_agreement([True, False, True, False], [True, False, True, False])
    assert a.accuracy == 1.0
    assert a.precision == 1.0
    assert a.recall == 1.0
    assert a.f1 == 1.0
    assert a.cohens_kappa == 1.0


def test_judge_misses_a_failure_counts_as_fn():
    # human says fail, judge says pass -> false negative (the dangerous error)
    a = compute_agreement([False], [True])
    assert a.fn == 1 and a.tp == 0
    assert a.recall == 0.0


def test_judge_overflags_counts_as_fp():
    a = compute_agreement([True], [False])
    assert a.fp == 1
    assert a.precision == 0.0


def test_mixed_metrics():
    judge = [True, True, False, False, True]
    human = [True, False, False, True, True]
    a = compute_agreement(judge, human)
    assert (a.tp, a.fp, a.fn, a.tn) == (2, 1, 1, 1)
    assert abs(a.accuracy - 0.6) < 1e-9
    assert abs(a.precision - (2 / 3)) < 1e-9
    assert abs(a.recall - (2 / 3)) < 1e-9


def test_kappa_chance_corrected():
    # all-pass labels with one judge mistake: kappa is defined and < 1
    a = compute_agreement([True, False, False, False], [False, False, False, False])
    assert a.cohens_kappa <= 0.0  # judge agreed by chance at best


def test_length_mismatch_raises():
    try:
        compute_agreement([True], [True, False])
        assert False, "should raise"
    except ValueError:
        pass


def test_sample_gold_set_loads_and_is_balanced():
    gold = load_gold(os.path.join(ROOT, "examples", "gold.jsonl"))
    assert len(gold) >= 12
    for ex in gold:
        assert "probe" in ex and "response" in ex and isinstance(ex["failure"], bool)
    fails = sum(1 for ex in gold if ex["failure"])
    passes = len(gold) - fails
    # a useful gold set has both classes
    assert fails >= 4 and passes >= 4


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"OK: {len(fns)} calibration tests passed")
