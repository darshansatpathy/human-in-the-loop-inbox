"""Which actions need a human, how many, and who.

Rules are checked in order; the first match decides. A rule matches on the action name (glob), the
risk the agent declared, and conditions on arguments. It can approve or deny automatically, or require
N approvals from reviewer groups, with an expiry and an escalation.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

Risk = Literal["low", "medium", "high", "critical"]


class Condition(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    gt: float | None = None
    gte: float | None = None
    lt: float | None = None
    lte: float | None = None
    eq: Any = None
    in_: list[Any] | None = Field(None, alias="in")
    not_in: list[Any] | None = None
    exists: bool | None = None

    def holds(self, args: dict[str, Any], key: str) -> bool:
        present = key in args
        if self.exists is not None and present != self.exists:
            return False
        if not present:
            return self.exists is False
        v = args[key]
        checks: list[bool] = []
        if any(x is not None for x in (self.gt, self.gte, self.lt, self.lte)):
            try:
                n = float(v)
            except (TypeError, ValueError):
                return False
            checks += [
                self.gt is None or n > self.gt,
                self.gte is None or n >= self.gte,
                self.lt is None or n < self.lt,
                self.lte is None or n <= self.lte,
            ]
        if self.eq is not None:
            checks.append(v == self.eq)
        if self.in_ is not None:
            checks.append(v in self.in_)
        if self.not_in is not None:
            checks.append(v not in self.not_in)
        return all(checks)


class Match(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = "*"
    risk: list[Risk] | None = None
    agent: str = "*"
    args: dict[str, Condition] = Field(default_factory=dict)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    match: Match = Field(default_factory=Match)
    decision: Literal["auto_approve", "auto_deny", "review"] = "review"
    approvals: int = Field(1, ge=1, le=5)
    approvers: list[str] = Field(default_factory=lambda: ["default"])
    ttl_minutes: int = Field(60, ge=1, le=60 * 24 * 14)
    escalate_after_minutes: int | None = None
    escalate_to: list[str] = Field(default_factory=list)
    notify: list[str] = Field(default_factory=list, description="slack:#channel or email:group")
    allow_edits: bool = True
    reason: str = ""

    def matches(self, agent: str, action: str, risk: str, args: dict[str, Any]) -> bool:
        m = self.match
        return (
            fnmatch.fnmatchcase(action, m.action)
            and fnmatch.fnmatchcase(agent, m.agent)
            and (m.risk is None or risk in m.risk)
            and all(c.holds(args, k) for k, c in m.args.items())
        )


class Policy(BaseModel):
    rules: list[Rule]
    default: Rule = Field(default_factory=lambda: Rule.model_validate({"name": "default"}))

    @classmethod
    def load(cls, path: Path) -> Policy:
        return cls.model_validate(yaml.safe_load(path.read_text()))

    def decide(self, agent: str, action: str, risk: str, args: dict[str, Any]) -> Rule:
        return next((r for r in self.rules if r.matches(agent, action, risk, args)), self.default)
