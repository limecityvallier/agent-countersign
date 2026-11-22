# agent-countersign

**An open governance layer for AI agents.**
Every tool call an agent makes goes through one gateway that applies a readable policy, sends sensitive actions to a human, redacts PII, enforces spend limits and writes a tamper-evident audit trail. It is vendor-neutral and speaks MCP, so Claude, ChatGPT, Copilot, Cursor and any other MCP client can use governed tools without code changes.

Companies are deploying agents from many vendors at once, and each vendor governs only its own. Nobody can answer the questions a CFO, CISO or auditor will ask: *What can this agent do? Who approved that? What did it cost? Can you prove the log wasn't edited?* agent-countersign answers them in one place, for every agent.

```
 agent ──► Gateway.call() ──► policy ──► allow ─────────────► tool ──► redact ──► agent
 (any vendor,                    │        deny  ────────────────────────────────► agent
  or MCP)                        │        require_approval ─► queue ─► human ─► resume()
                                 └──────► audit trail (every step, hash-chained)
```

## What it does

| Control | How |
|---|---|
| **Policy as plain YAML** | Rules a process owner can read and sign off on. First match wins; anything not covered is denied. Match on agent, tool and argument values (`amount > 500`, regex, lists). |
| **Human in the loop** | `require_approval` rules queue the call. Named approvers decide from the CLI (or your own UI). Agents can't approve their own requests, and approvals are single-use. |
| **Tamper-evident audit** | Every decision, approval and execution is logged with a SHA-256 chain. Edit or delete one row and `countersign verify` names the event where the chain breaks. |
| **PII redaction** | Emails, phone numbers, SSNs and card numbers (Luhn-checked) are stripped from the audit log and from what the model sees. Tools look up sensitive values themselves, so the model never needs them. |
| **Spend limits** | Give each tool a cost; set daily budgets per agent. |
| **MCP adapter** | Wrap your tools once; every MCP client gets the governed versions plus `countersign_check_approval`. |

## Quick start

```bash
pip install -e ".[mcp]"
python examples/overdue_invoices/run_demo.py
```

The demo runs a scripted accounts-receivable agent with no LLM, so you can see every control fire: an allowed lookup with redacted output, a customer email held for approval, a $900 refund blocked by policy, a self-approval refused, the approved email sent, a replay refused, and then tampering with the audit log detected.

## Use it in your code

```python
from agent_countersign import Gateway

gw = Gateway("policy.yaml", "countersign.db")

@gw.tool(cost_usd=0.01)
def send_email(customer_id: int, subject: str, body: str) -> str:
    """Send an email to a customer."""
    ...

result = gw.call("billing-bot", "send_email", {"customer_id": 1, "subject": "...", "body": "..."})
result.status        # "executed" | "denied" | "pending" | "failed"
```

## Policy example

```yaml
defaults:
  decision: deny
budgets:
  - {agent: "*", daily_usd: 1.00}
rules:
  - name: read-only lookups
    tools: [list_overdue_invoices, get_customer]
    decision: allow
  - name: no refunds over $500
    tools: [issue_refund]
    when: {amount: {gt: 500}}
    decision: deny
  - name: customer emails need a human
    tools: [send_email]
    decision: require_approval
    approvers: [ar-manager, controller]
```

Dry-run a decision before you deploy:

```bash
countersign check policy.yaml issue_refund agent=billing-bot amount=200
# require_approval  (rule: small refunds need the controller)  approvers: controller
```

## Governed MCP server

```python
from agent_countersign.mcp_adapter import build_server
build_server(gw, agent="billing-bot").run()
```

See `examples/overdue_invoices/server.py` for a ready-to-run server and Claude Desktop config. Approve from a terminal:

```bash
countersign approvals
countersign approve 1 --by ar-manager --note "tone is fine"
countersign audit
countersign verify
```

## Roadmap

- Authenticated approvers (SSO / signed approvals)
- MCP **proxy** mode: govern any existing MCP server without touching its code
- Approvals in Slack, Teams and email
- Per-model cost tracking from LLM usage data
- Signed audit checkpoints and export for SOX/HIPAA evidence
- Policy packs for common regulated workflows (AP/AR, healthcare scheduling, claims)
- Postgres store and a small web console

## Status

v0.1. Small core, fully tested, meant to be read in an afternoon. Issues and pull requests welcome.

Known limits in v0.1: approver identity comes from `--by` and is not yet authenticated (put the CLI behind your own access controls, or wire approvals to SSO); redaction is pattern-based and is a safety net, not a substitute for keeping sensitive data out of model context by design.

## License

Apache-2.0
