import asyncio

import pytest

from agent_warden import ApprovalError, Decision, Gateway, Policy, PolicyError, redact
from agent_warden.cli import main as cli

POLICY = """
defaults: {decision: deny}
budgets:
  - {agent: "*", daily_usd: 0.05}
rules:
  - {name: reads, tools: [lookup], decision: allow}
  - name: big refunds blocked
    tools: [refund]
    when: {amount: {gt: 500}}
    decision: deny
    reason: too big
  - {name: refunds, tools: [refund], decision: require_approval, approvers: [controller]}
  - {name: pricey, tools: [pricey], decision: allow}
"""


@pytest.fixture
def gw(tmp_path):
    g = Gateway(Policy.from_yaml(POLICY), tmp_path / "w.db")
    calls = []

    @g.tool()
    def lookup(customer_id: int) -> dict:
        return {"id": customer_id, "email": "jane@corp.example", "phone": "555-201-3344"}

    @g.tool()
    def refund(customer_id: int, amount: float) -> str:
        calls.append(amount)
        return f"refunded {amount}"

    @g.tool(cost_usd=0.03)
    def pricey() -> str:
        return "ok"

    @g.tool()
    def unruled() -> str:
        return "should never run"

    g.calls = calls
    return g


def test_allow_runs_and_redacts_output(gw):
    r = gw.call("bot", "lookup", {"customer_id": 1})
    assert r.status == "executed"
    assert r.output["email"] == "[REDACTED:EMAIL]"
    assert r.output["phone"] == "[REDACTED:PHONE]"


def test_condition_denies(gw):
    r = gw.call("bot", "refund", {"customer_id": 1, "amount": 900})
    assert r.status == "denied" and r.reason == "too big"
    assert gw.calls == []


def test_default_deny_and_unknown_tool(gw):
    assert gw.call("bot", "unruled").status == "denied"
    assert gw.call("bot", "nope").rule == "unknown-tool"


def test_approval_flow_single_use(gw):
    r = gw.call("bot", "refund", {"customer_id": 1, "amount": 50})
    assert r.status == "pending" and gw.calls == []
    assert gw.resume(r.approval_id).status == "pending"
    with pytest.raises(ApprovalError):
        gw.approve(r.approval_id, by="bot")          # self-approval
    with pytest.raises(ApprovalError):
        gw.approve(r.approval_id, by="intern")       # not an approver
    gw.approve(r.approval_id, by="controller")
    done = gw.resume(r.approval_id)
    assert done.status == "executed" and gw.calls == [50]
    assert gw.resume(r.approval_id).status == "failed"   # cannot replay
    assert gw.calls == [50]


def test_denied_approval(gw):
    r = gw.call("bot", "refund", {"customer_id": 1, "amount": 50})
    gw.deny(r.approval_id, by="controller", note="wrong customer")
    out = gw.resume(r.approval_id)
    assert out.status == "denied" and "wrong customer" in out.reason
    assert gw.calls == []


def test_budget(gw):
    assert gw.call("bot", "pricey").status == "executed"
    r = gw.call("bot", "pricey")
    assert r.status == "denied" and r.rule == "budget"
    assert gw.call("other-bot", "pricey").status == "executed"   # budgets are per agent


def test_audit_chain_detects_tampering(gw):
    gw.call("bot", "lookup", {"customer_id": 1})
    gw.call("bot", "refund", {"customer_id": 1, "amount": 900})
    assert gw.store.verify_chain() == (True, None)
    gw.store._db.execute("UPDATE audit SET decision='allow' WHERE decision='deny'")
    ok, bad = gw.store.verify_chain()
    assert not ok and bad is not None


def test_audit_args_are_redacted(gw):
    gw.call("bot", "lookup", {"customer_id": 1, "note": "call 555-201-3344"})
    assert "555-201-3344" not in str(gw.store.events())


def test_redact_card_needs_luhn():
    assert redact("card 4111 1111 1111 1111") == "card [REDACTED:CARD]"
    assert redact("order 1234 5678 9012 3456") == "order 1234 5678 9012 3456"
    assert redact({"x": ["ssn 123-45-6789"]}) == {"x": ["ssn [REDACTED:SSN]"]}


def test_policy_validation():
    with pytest.raises(PolicyError):
        Policy.from_yaml("rules: [{name: x, decision: maybe}]")
    with pytest.raises(PolicyError):
        Policy.from_yaml("rules: [{name: x, decision: allow, when: {a: {bigger: 1}}}]")
    p = Policy.from_yaml("rules: [{tools: ['read_*'], agents: ['ops-*'], decision: allow}]")
    assert p.evaluate("ops-bot", "read_file", {}).decision is Decision.ALLOW
    assert p.evaluate("sales-bot", "read_file", {}).decision is Decision.DENY


def test_cli(gw, tmp_path, capsys):
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    r = gw.call("bot", "refund", {"customer_id": 1, "amount": 50})
    db = gw.store.path
    assert cli(["--db", db, "approvals"]) == 0
    assert f"#{r.approval_id}" in capsys.readouterr().out
    assert cli(["--db", db, "--policy", str(pol), "approve", str(r.approval_id), "--by", "controller"]) == 0
    assert cli(["--db", db, "verify"]) == 0
    assert cli(["check", str(pol), "refund", "agent=bot", "amount=900"]) == 0
    assert "deny" in capsys.readouterr().out


def test_mcp_adapter(gw):
    pytest.importorskip("mcp")
    from agent_warden.mcp_adapter import build_server

    server = build_server(gw, agent="bot")

    async def run():
        names = {t.name for t in await server.list_tools()}
        assert {"lookup", "refund", "warden_check_approval"} <= names
        res = await server.call_tool("refund", {"customer_id": 1, "amount": 50})
        assert res.structured_content["status"] == "pending"
        gw.approve(res.structured_content["approval_id"], by="controller")
        res = await server.call_tool("warden_check_approval",
                                     {"approval_id": res.structured_content["approval_id"]})
        assert res.structured_content["status"] == "executed"

    asyncio.run(run())
