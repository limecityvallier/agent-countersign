"""The Gateway: the single path every agent tool call goes through.

    agent ──► Gateway.call() ──► policy ──► allow ────────► tool ──► redact ──► agent
                                    │        deny  ─────────────────────────────► agent
                                    │        approval ─► queue ─► human ─► resume()
                                    └──────► audit trail (every step, hash-chained)
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .policy import Decision, Policy
from .redact import redact
from .store import Store


class ApprovalError(RuntimeError):
    pass


@dataclass
class Tool:
    name: str
    fn: Callable[..., Any]
    cost_usd: float = 0.0
    description: str = ""


@dataclass
class Result:
    status: str                      # executed | denied | pending | failed
    output: Any = None
    reason: str = ""
    rule: str = ""
    approval_id: int | None = None
    approvers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"status": self.status}
        if self.status == "executed":
            d["output"] = self.output
        if self.reason:
            d["reason"] = self.reason
        if self.rule:
            d["rule"] = self.rule
        if self.approval_id is not None:
            d["approval_id"] = self.approval_id
        if self.status == "pending":
            d["message"] = ("This action needs human approval. Tell the user it is waiting "
                            f"for approval #{self.approval_id}; check back later.")
        return d


class Gateway:
    def __init__(self, policy: Policy | str | Path, store: Store | str | Path = "countersign.db"):
        self.policy = policy if isinstance(policy, Policy) else Policy.from_file(policy)
        self.store = store if isinstance(store, Store) else Store(store)
        self.tools: dict[str, Tool] = {}

    # ---- registration --------------------------------------------------

    def tool(self, name: str | None = None, *, cost_usd: float = 0.0):
        """Decorator: register a function as a governed tool."""
        def wrap(fn: Callable[..., Any]) -> Callable[..., Any]:
            self.register(fn, name=name, cost_usd=cost_usd)
            return fn
        return wrap

    def register(self, fn: Callable[..., Any], *, name: str | None = None,
                 cost_usd: float = 0.0) -> None:
        tool_name = name or fn.__name__
        self.tools[tool_name] = Tool(tool_name, fn, cost_usd, inspect.getdoc(fn) or "")

    # ---- the governed call --------------------------------------------

    def call(self, agent: str, tool: str, args: dict[str, Any] | None = None) -> Result:
        args = dict(args or {})
        logged_args = redact(args) if self.policy.redact_audit else args

        if tool not in self.tools:
            self.store.log(agent=agent, tool=tool, args=logged_args, event="decided",
                           decision="deny", rule="unknown-tool", detail="Tool is not registered.")
            return Result("denied", reason=f"Unknown tool '{tool}'.", rule="unknown-tool")

        verdict = self.policy.evaluate(agent, tool, args)

        if verdict.decision is Decision.DENY:
            self.store.log(agent=agent, tool=tool, args=logged_args, event="decided",
                           decision="deny", rule=verdict.rule, detail=verdict.reason)
            return Result("denied", reason=verdict.reason or "Blocked by policy.", rule=verdict.rule)

        budget_block = self._over_budget(agent, tool)
        if budget_block:
            self.store.log(agent=agent, tool=tool, args=logged_args, event="decided",
                           decision="deny", rule="budget", detail=budget_block)
            return Result("denied", reason=budget_block, rule="budget")

        if verdict.decision is Decision.REQUIRE_APPROVAL:
            approval_id = self.store.create_approval(agent=agent, tool=tool, args=args,
                                                     rule=verdict.rule, approvers=verdict.approvers)
            self.store.log(agent=agent, tool=tool, args=logged_args, event="decided",
                           decision="require_approval", rule=verdict.rule,
                           detail=verdict.reason, approval_id=approval_id)
            return Result("pending", reason=verdict.reason, rule=verdict.rule,
                          approval_id=approval_id, approvers=verdict.approvers)

        self.store.log(agent=agent, tool=tool, args=logged_args, event="decided",
                       decision="allow", rule=verdict.rule)
        return self._execute(agent, tool, args, logged_args, rule=verdict.rule)

    # ---- approvals -----------------------------------------------------

    def approve(self, approval_id: int, *, by: str, note: str | None = None) -> None:
        a = self._pending(approval_id, by)
        self.store.set_approval_status(approval_id, "approved", by=by, note=note)
        self.store.log(agent=a.agent, tool=a.tool, args=self._log_args(a.args), event="approved",
                       rule=a.rule, actor=by, detail=note, approval_id=approval_id)

    def deny(self, approval_id: int, *, by: str, note: str | None = None) -> None:
        a = self._pending(approval_id, by)
        self.store.set_approval_status(approval_id, "denied", by=by, note=note)
        self.store.log(agent=a.agent, tool=a.tool, args=self._log_args(a.args), event="denied",
                       rule=a.rule, actor=by, detail=note, approval_id=approval_id)

    def resume(self, approval_id: int) -> Result:
        """Run an approved call, or report where it stands. Safe to call repeatedly."""
        a = self.store.get_approval(approval_id)
        if a is None:
            return Result("failed", reason=f"No approval #{approval_id}.")
        if a.status == "pending":
            return Result("pending", reason="Still waiting for a human decision.",
                          rule=a.rule, approval_id=approval_id, approvers=a.approvers)
        if a.status == "denied":
            return Result("denied", reason=f"Denied by {a.decided_by}" +
                          (f": {a.note}" if a.note else "."), rule=a.rule)
        if a.status == "executed":
            return Result("failed", reason="Already executed; approvals are single-use.", rule=a.rule)
        budget_block = self._over_budget(a.agent, a.tool)
        if budget_block:
            return Result("denied", reason=budget_block, rule="budget")
        self.store.set_approval_status(approval_id, "executed")
        return self._execute(a.agent, a.tool, a.args, self._log_args(a.args),
                             rule=a.rule, approval_id=approval_id, actor=a.decided_by)

    # ---- internals -----------------------------------------------------

    def _pending(self, approval_id: int, by: str):
        a = self.store.get_approval(approval_id)
        if a is None:
            raise ApprovalError(f"No approval #{approval_id}.")
        if a.status != "pending":
            raise ApprovalError(f"Approval #{approval_id} is already {a.status}.")
        if by == a.agent:
            raise ApprovalError("An agent cannot approve its own request.")
        if a.approvers and by not in a.approvers:
            raise ApprovalError(f"'{by}' is not an approver for rule '{a.rule}' "
                                f"(allowed: {', '.join(a.approvers)}).")
        return a

    def _log_args(self, args: dict[str, Any]) -> dict[str, Any]:
        return redact(args) if self.policy.redact_audit else args

    def _over_budget(self, agent: str, tool: str) -> str:
        budget = self.policy.budget_for(agent)
        cost = self.tools[tool].cost_usd if tool in self.tools else 0.0
        if budget and cost and self.store.spend_today(agent) + cost > budget.daily_usd:
            return (f"Daily budget of ${budget.daily_usd:.2f} for '{agent}' would be exceeded "
                    f"(spent ${self.store.spend_today(agent):.2f}, this call ${cost:.2f}).")
        return ""

    def _execute(self, agent: str, tool: str, args: dict[str, Any], logged_args: dict[str, Any],
                 *, rule: str, approval_id: int | None = None, actor: str | None = None) -> Result:
        t = self.tools[tool]
        try:
            output = t.fn(**args)
        except Exception as exc:  # the agent gets a clean error, the audit gets the detail
            self.store.log(agent=agent, tool=tool, args=logged_args, event="failed", rule=rule,
                           detail=f"{type(exc).__name__}: {exc}", approval_id=approval_id, actor=actor)
            return Result("failed", reason=f"Tool error: {exc}", rule=rule)
        self.store.log(agent=agent, tool=tool, args=logged_args, event="executed", rule=rule,
                       approval_id=approval_id, actor=actor, cost_usd=t.cost_usd)
        if self.policy.redact_outputs:
            output = redact(output)
        return Result("executed", output=output, rule=rule, approval_id=approval_id)
