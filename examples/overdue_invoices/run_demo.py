"""Walk through agent-countersign end to end without an LLM.

A scripted "billing-bot" agent chases overdue invoices. Watch what the
gateway allows, blocks, redacts and sends to a human, then check the
audit trail and see what happens when someone tampers with it.

    python examples/overdue_invoices/run_demo.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "src"))

from agent_countersign import ApprovalError, Gateway  # noqa: E402
from tools import make_business_db, register_tools  # noqa: E402

AGENT = "billing-bot"


def show(step: str, result) -> None:
    print(f"\n▶ {step}")
    print("  " + json.dumps(result.to_dict(), indent=2, default=str).replace("\n", "\n  "))


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="countersign-demo-"))
    gw = Gateway(HERE / "policy.yaml", work / "countersign.db")
    register_tools(gw, make_business_db(work / "business.db"))

    show("Agent lists overdue invoices (allowed: read-only)",
         gw.call(AGENT, "list_overdue_invoices", {"min_days": 14}))

    show("Agent looks up a customer (allowed, but email and phone are redacted before the model sees them)",
         gw.call(AGENT, "get_customer", {"customer_id": 1}))

    pending = gw.call(AGENT, "send_email", {
        "customer_id": 1, "subject": "Invoice INV-1042 is 47 days past due",
        "body": "Hi, a friendly reminder that INV-1042 for $1,840.00 is past due."})
    show("Agent drafts a reminder email (held for human approval)", pending)

    show("Agent tries a $900 refund (blocked outright by policy)",
         gw.call(AGENT, "issue_refund", {"customer_id": 2, "amount": 900}))

    show("Agent tries a tool nobody gave it (denied)",
         gw.call(AGENT, "delete_customer", {"customer_id": 3}))

    print("\n▶ The agent tries to approve its own request")
    try:
        gw.approve(pending.approval_id, by=AGENT)
    except ApprovalError as exc:
        print(f"  refused: {exc}")

    print("\n▶ Someone who isn't an approver tries")
    try:
        gw.approve(pending.approval_id, by="intern")
    except ApprovalError as exc:
        print(f"  refused: {exc}")

    print("\n▶ The AR manager approves it")
    gw.approve(pending.approval_id, by="ar-manager", note="Tone is fine, send it.")
    show("Agent checks back and the email goes out", gw.resume(pending.approval_id))
    show("Agent tries to reuse the same approval (approvals are single-use)", gw.resume(pending.approval_id))

    print("\n▶ Audit trail (args already redacted)")
    for e in gw.store.events():
        extra = " ".join(f"{k}={e[k]}" for k in ("decision", "rule", "actor") if e[k])
        print(f"  #{e['id']:<2} {e['event']:<9} {e['tool']:<22} {extra}")

    ok, _ = gw.store.verify_chain()
    print(f"\n▶ Verify chain: {'intact' if ok else 'BROKEN'}")

    refund_event = next(e["id"] for e in gw.store.events() if e["tool"] == "issue_refund")
    print(f"▶ Someone edits event #{refund_event} in the database to hide the blocked refund...")
    gw.store._db.execute("UPDATE audit SET decision = 'allow' WHERE id = ?", (refund_event,))
    gw.store._db.commit()
    ok, bad = gw.store.verify_chain()
    print(f"▶ Verify chain: {'intact' if ok else f'TAMPERING DETECTED at event #{bad}'}")
    print(f"\nFiles left in {work} so you can try the CLI, e.g.:\n"
          f"  countersign --db {work / 'countersign.db'} audit")


if __name__ == "__main__":
    main()
