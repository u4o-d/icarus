"""
Vulnerable MCP server — minimal Phase 2 version.

This server is intentionally insecure. In later phases it will implement
six documented MCP attack patterns (tool poisoning, rug pull, BOLA, full-
schema poisoning, cross-server shadowing, direct injection) as targets
for the Sentinel guardrails layer.

In Phase 2, it exposes exactly one tool — view_user_profile — to prove the
FastMCP plumbing works end-to-end before we layer the attacks on top.

DO NOT DEPLOY. See docs/threat_model.md.
"""

import logging
import os

from fastmcp import FastMCP

from icarus.data import db_manager

logger = logging.getLogger(__name__)

# ─── Server setup ────────────────────────────────────────────────────────────

mcp = FastMCP("vulnerable-mcp")


# ─── Tools ───────────────────────────────────────────────────────────────────


@mcp.tool()
def view_user_profile(user_id: str) -> dict:
    """
    Return a user's full profile.

    Args:
        user_id: The ID of the user to look up.

    Returns:
        A dict with fullname, role, credit_card, email, access_token.
        Returns {"error": "not_found"} if the user does not exist.

    Note: This tool intentionally has no authorization check. Any caller
    can request any user's profile. This is the vulnerability that
    Attack 2 (BOLA) exploits and that the L3 Sentinel layer defends.
    """
    user = db_manager.get_user(user_id)
    if user is None:
        return {"error": "not_found", "user_id": user_id}
    return user


# ─── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | vulnerable-mcp | %(message)s",
    )

    host = os.environ.get("VULNERABLE_MCP_HOST", "127.0.0.1")
    port = int(os.environ.get("VULNERABLE_MCP_PORT", "9001"))

    logger.info("Starting vulnerable MCP server on %s:%d", host, port)
    mcp.run(transport="http", host=host, port=port)
