"""Command line for the humans in the loop.

    warden approvals                    list what is waiting
    warden approve 3 --by finance-lead  approve request #3
    warden deny 3 --by finance-lead --note "wrong customer"
    warden audit --limit 20             show the latest audit events
    warden verify                       check the audit trail has not been tampered with
    warden check policy.yaml send_email agent=billing-bot customer_id=7
                                        dry-run a policy decision
"""

from __future__ import annotations

import argparse
import json
import sys

from .gateway import ApprovalError, Gateway
from .policy import Policy, PolicyError
from .store import Store


def _parse_kv(pairs: list[str]) -> dict[str, object]:
    out: dict[str, object] = {}
    for pair in pairs:
        key, _, raw = pair.partition("=")
        try:
            out[key] = json.loads(raw)
        except json.JSONDecodeError:
            out[key] = raw
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="warden", description="Governance for AI agent tool calls.")
    ap.add_argument("--db", default="warden.db", help="SQLite store (default: warden.db)")
    ap.add_argument("--policy", default="policy.yaml", help="Policy file (default: policy.yaml)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("approvals", help="List approval requests")
    p.add_argument("--all", action="store_true", help="Include decided requests")

    for name in ("approve", "deny"):
        p = sub.add_parser(name, help=f"{name.title()} a pending request")
        p.add_argument("id", type=int)
        p.add_argument("--by", required=True, help="Your name or role, as listed in the policy")
        p.add_argument("--note", default=None)

    p = sub.add_parser("audit", help="Show audit events")
    p.add_argument("--limit", type=int, default=20)

    sub.add_parser("verify", help="Verify the audit hash chain")

    p = sub.add_parser("check", help="Dry-run a policy decision")
    p.add_argument("policy_file")
    p.add_argument("tool")
    p.add_argument("pairs", nargs="*", help="agent=NAME and key=value arguments")

    a = ap.parse_args(argv)

    if a.cmd == "check":
        try:
            policy = Policy.from_file(a.policy_file)
        except PolicyError as exc:
            print(f"Invalid policy: {exc}")
            return 2
        kv = _parse_kv(a.pairs)
        agent = str(kv.pop("agent", "*"))
        v = policy.evaluate(agent, a.tool, kv)
        print(f"{v.decision.value}  (rule: {v.rule})" + (f"  approvers: {', '.join(v.approvers)}" if v.approvers else ""))
        return 0

    store = Store(a.db)

    if a.cmd == "approvals":
        rows = store.list_approvals(None if a.all else "pending")
        if not rows:
            print("Nothing waiting.")
        for r in rows:
            who = f" by {r.decided_by}" if r.decided_by else ""
            print(f"#{r.id}  {r.status:<9} {r.agent} -> {r.tool}({json.dumps(r.args)})  "
                  f"rule={r.rule}  approvers={','.join(r.approvers) or 'any'}{who}")
        return 0

    if a.cmd in ("approve", "deny"):
        gw = Gateway(Policy.from_file(a.policy), store)
        try:
            getattr(gw, a.cmd)(a.id, by=a.by, note=a.note)
        except ApprovalError as exc:
            print(f"Error: {exc}")
            return 1
        print(f"#{a.id} {a.cmd}d by {a.by}.")
        return 0

    if a.cmd == "audit":
        for e in store.events(a.limit):
            extra = " ".join(f"{k}={e[k]}" for k in ("decision", "rule", "actor", "approval_id") if e[k])
            print(f"{e['id']:>4} {e['ts'][:19]} {e['event']:<9} {e['agent']} -> {e['tool']}  {extra}"
                  + (f"  ({e['detail']})" if e["detail"] else ""))
        return 0

    if a.cmd == "verify":
        ok, bad = store.verify_chain()
        n = len(store.events())
        print(f"OK: {n} events, chain intact." if ok else f"TAMPERED: chain breaks at event #{bad}.")
        return 0 if ok else 1

    return 1


if __name__ == "__main__":
    sys.exit(main())
