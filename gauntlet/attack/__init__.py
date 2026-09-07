"""Gauntlet adaptive attack engine.

An adaptive, research-grounded attacker that, given a GOAL, iteratively searches
for an input that makes your agent fail, using the agent's own responses as
feedback. Zero third-party dependencies; every default path is offline and
deterministic. Optional LLM attacker is injectable (see ``models.LLMAttacker``).

Strategies adapt published work: Best-of-N (Hughes et al. 2024, 2412.03556),
PAIR (Chao et al. 2023, 2310.08419), TAP (Mehrotra et al. 2023, 2312.02119),
Crescendo (Russinovich et al. 2024, 2404.01833).
"""

from .objective import (
    Goal, Response, ObjectiveScore, score,
    goals_from_canaries, goal_from_spec,
)
from .mutators import MUTATORS, AUGMENTERS, FRAMERS, apply_named, compose
from .models import AttackerModel, HeuristicAttacker, LLMAttacker, get_attacker
from .strategies import (
    Attempt, AttackResult, STRATEGIES, get_strategy,
    best_of_n, pair, tap, crescendo, rainbow,
)
from .engine import run_attack, AttackReport, http_send, callable_send

__all__ = [
    "Goal", "Response", "ObjectiveScore", "score",
    "goals_from_canaries", "goal_from_spec",
    "MUTATORS", "AUGMENTERS", "FRAMERS", "apply_named", "compose",
    "AttackerModel", "HeuristicAttacker", "LLMAttacker", "get_attacker",
    "Attempt", "AttackResult", "STRATEGIES", "get_strategy",
    "best_of_n", "pair", "tap", "crescendo", "rainbow",
    "run_attack", "AttackReport", "http_send", "callable_send",
]
