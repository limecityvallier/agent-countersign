"""Policy engine: decides whether an agent may call a tool with given arguments.

Policies are plain YAML so the people accountable for a process (not just
engineers) can read and review them. Rules are evaluated top to bottom and the
first matching rule wins. If nothing matches, the default decision applies,
which is ``deny`` unless the policy says otherwise.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


_OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "matches"}


class PolicyError(ValueError):
    """Raised when a policy file is malformed."""


@dataclass
class Rule:
    name: str
    decision: Decision
    agents: list[str] = field(default_factory=lambda: ["*"])
    tools: list[str] = field(default_factory=lambda: ["*"])
    when: dict[str, dict[str, Any]] = field(default_factory=dict)
    approvers: list[str] = field(default_factory=list)
    reason: str = ""

    def matches(self, agent: str, tool: str, args: dict[str, Any]) -> bool:
        if not any(fnmatch.fnmatchcase(agent, p) for p in self.agents):
            return False
        if not any(fnmatch.fnmatchcase(tool, p) for p in self.tools):
            return False
        return all(_check(args.get(arg), cond) for arg, cond in self.when.items())


@dataclass
class Budget:
    agent: str
    daily_usd: float


@dataclass
class Verdict:
    decision: Decision
    rule: str
    reason: str = ""
    approvers: list[str] = field(default_factory=list)


@dataclass
class Policy:
    rules: list[Rule]
    default: Decision = Decision.DENY
    budgets: list[Budget] = field(default_factory=list)
    redact_audit: bool = True
    redact_outputs: bool = True

    def evaluate(self, agent: str, tool: str, args: dict[str, Any]) -> Verdict:
        for rule in self.rules:
            if rule.matches(agent, tool, args):
                return Verdict(rule.decision, rule.name, rule.reason, list(rule.approvers))
        return Verdict(self.default, "default", "No rule matched this call.")

    def budget_for(self, agent: str) -> Budget | None:
        for b in self.budgets:
            if fnmatch.fnmatchcase(agent, b.agent):
                return b
        return None

    # ---- loading -------------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        return cls.from_dict(yaml.safe_load(Path(path).read_text()))

    @classmethod
    def from_yaml(cls, text: str) -> "Policy":
        return cls.from_dict(yaml.safe_load(text))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        if not isinstance(data, dict):
            raise PolicyError("Policy must be a mapping.")
        defaults = data.get("defaults") or {}
        rules = []
        for i, raw in enumerate(data.get("rules") or []):
            name = raw.get("name") or f"rule-{i + 1}"
            try:
                decision = Decision(raw["decision"])
            except (KeyError, ValueError) as exc:
                raise PolicyError(f"Rule '{name}': decision must be one of "
                                  f"{[d.value for d in Decision]}") from exc
            when = raw.get("when") or {}
            for arg, cond in when.items():
                if not isinstance(cond, dict) or not set(cond) <= _OPERATORS:
                    raise PolicyError(f"Rule '{name}': condition on '{arg}' must use "
                                      f"operators {sorted(_OPERATORS)}")
            rules.append(Rule(
                name=name,
                decision=decision,
                agents=_as_list(raw.get("agents", ["*"])),
                tools=_as_list(raw.get("tools", ["*"])),
                when=when,
                approvers=_as_list(raw.get("approvers", [])),
                reason=raw.get("reason", ""),
            ))
        budgets = [Budget(agent=b.get("agent", "*"), daily_usd=float(b["daily_usd"]))
                   for b in data.get("budgets") or []]
        return cls(
            rules=rules,
            default=Decision(defaults.get("decision", "deny")),
            budgets=budgets,
            redact_audit=bool(defaults.get("redact_audit", True)),
            redact_outputs=bool(defaults.get("redact_outputs", True)),
        )


def _as_list(value: Any) -> list[str]:
    return [value] if isinstance(value, str) else list(value)


def _check(value: Any, cond: dict[str, Any]) -> bool:
    for op, expected in cond.items():
        if op == "eq" and value != expected:
            return False
        if op == "ne" and value == expected:
            return False
        if op == "in" and value not in expected:
            return False
        if op == "not_in" and value in expected:
            return False
        if op == "matches" and (value is None or not re.search(expected, str(value))):
            return False
        if op in {"gt", "gte", "lt", "lte"}:
            try:
                v = float(value)
            except (TypeError, ValueError):
                return False
            if op == "gt" and not v > expected:
                return False
            if op == "gte" and not v >= expected:
                return False
            if op == "lt" and not v < expected:
                return False
            if op == "lte" and not v <= expected:
                return False
    return True
