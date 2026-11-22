"""agent-countersign: an open governance layer for AI agents.

Every tool call an agent makes passes through one gateway that applies a
readable policy, routes sensitive actions to a human, redacts PII, enforces
spend limits, and writes a tamper-evident audit trail. Vendor-neutral: it
works with any agent framework, and speaks MCP so Claude, ChatGPT, Copilot
and other MCP clients can use governed tools directly.
"""

from .gateway import ApprovalError, Gateway, Result, Tool
from .policy import Decision, Policy, PolicyError
from .redact import redact
from .store import Store

__all__ = ["Gateway", "Result", "Tool", "ApprovalError", "Policy", "PolicyError",
           "Decision", "Store", "redact"]
__version__ = "0.1.0"
