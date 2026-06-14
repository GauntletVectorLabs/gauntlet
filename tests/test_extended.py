"""Extended probe set is opt-in and doesn't disturb the default suite."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "examples"))

from gauntlet.adversaries import builtin_probes, builtin_extended, builtin_multiturn  # noqa: E402


def test_default_suite_unchanged():
    # The benchmark cites this count; extended/multiturn must not change it.
    assert len(builtin_probes()) == 15


def test_extended_set_present_and_distinct():
    ext = builtin_extended()
    assert len(ext) >= 8
    ids = [p.id for p in ext]
    assert len(ids) == len(set(ids))                  # unique ids
    base_ids = {p.id for p in builtin_probes()}
    assert not (set(ids) & base_ids)                  # disjoint from default
    # newer categories are represented
    cats = {p.category for p in ext}
    for c in ("indirect_injection", "homoglyph_evasion", "refusal_suppression",
              "encoding_smuggling", "pii_handling"):
        assert c in cats


def test_extended_probes_are_well_formed():
    for p in builtin_extended():
        assert p.id and p.category and p.message
        assert isinstance(p.should_refuse, bool)


def test_extended_flags_a_leaky_agent():
    # The fragile sample agent leaks on injection-style messages -> extended
    # prompt-extraction probes should surface findings.
    from sample_agent import reply
    leaks = 0
    for p in builtin_extended():
        if "INTERNAL-OPS-KEY-7731" in reply(p.message):
            leaks += 1
    assert leaks >= 1


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"OK: {len(fns)} extended tests passed")
