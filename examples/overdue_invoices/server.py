"""Run the demo tools as a governed MCP server (stdio).

Add to Claude Desktop / Claude Code (or any MCP client), for example:

    {
      "mcpServers": {
        "billing": {
          "command": "python",
          "args": ["/path/to/agent-warden/examples/overdue_invoices/server.py"]
        }
      }
    }

Then ask: "Chase our overdue invoices." Approve requests from a terminal:

    cd examples/overdue_invoices
    warden approvals
    warden approve 1 --by ar-manager
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "src"))

from agent_warden import Gateway  # noqa: E402
from agent_warden.mcp_adapter import build_server  # noqa: E402
from tools import make_business_db, register_tools  # noqa: E402

if __name__ == "__main__":
    gw = Gateway(HERE / "policy.yaml", HERE / "warden.db")
    register_tools(gw, make_business_db(HERE / "business.db"))
    build_server(gw, agent="billing-bot", name="billing (governed)").run()
