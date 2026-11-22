"""Expose governed tools over MCP (Model Context Protocol).

Any MCP client (Claude Desktop, Claude Code, ChatGPT, Copilot, Cursor and
others) sees the same tools it would see without agent-warden, but every call
is checked, approved, redacted and audited by the Gateway first. One extra
tool, ``warden_check_approval``, lets the agent pick up a call a human has
since approved.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any

from mcp.server.mcpserver import MCPServer

from .gateway import Gateway


def build_server(gateway: Gateway, agent: str, name: str = "agent-warden") -> MCPServer:
    server = MCPServer(name=name, instructions=(
        "Tools here are governed. Some calls run immediately, some are blocked, and some "
        "wait for a human. When a result says 'pending', tell the user which approval it "
        "is waiting on; later, call warden_check_approval with that id."))

    for tool in gateway.tools.values():
        server.add_tool(_governed(gateway, agent, tool.name, tool.fn),
                        name=tool.name, description=tool.description or None)

    def warden_check_approval(approval_id: int) -> dict[str, Any]:
        """Check a pending approval. If a human approved it, the action runs now and its result is returned."""
        return gateway.resume(approval_id).to_dict()

    server.add_tool(warden_check_approval, name="warden_check_approval")
    return server


def _governed(gateway: Gateway, agent: str, tool_name: str, fn):
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(**kwargs: Any) -> dict[str, Any]:
        return gateway.call(agent, tool_name, kwargs).to_dict()

    # Keep the original parameters so the MCP schema is unchanged, but always return a dict.
    wrapper.__signature__ = sig.replace(return_annotation=dict[str, Any])  # type: ignore[attr-defined]
    wrapper.__annotations__ = {**getattr(fn, "__annotations__", {}), "return": dict[str, Any]}
    del wrapper.__wrapped__
    return wrapper
