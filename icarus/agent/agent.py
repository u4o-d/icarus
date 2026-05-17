"""
ICARUS agent — Phase 3 baseline (no guardrails).

Connects to the vulnerable MCP server, exposes its tools to an OpenAI
chat completion, executes whatever tool calls the LLM proposes, and
returns the final response to the user.

This is the unprotected baseline. There is no input scanning, no output
redaction, no authorization on tool calls. Attacks against this agent
succeed. Phases 5–7 add the Sentinel layers that stop them.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from fastmcp import Client as MCPClient
from openai import AsyncOpenAI

from icarus.agent.prompts import build_system_prompt

logger = logging.getLogger(__name__)

# Maximum tool-call iterations per user turn. Prevents runaway loops
# where the LLM keeps calling tools forever.
MAX_TOOL_ITERATIONS = 5


@dataclass
class AgentSession:
    """
    Per-user agent session.

    Holds the authenticated user identity, the conversation history, and
    the MCP client connection. One instance per user session.
    """

    user_id: str
    role: str
    mcp_url: str
    model: str = field(default_factory=lambda: os.environ.get("AGENT_MODEL", "gpt-4o"))
    messages: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        # Seed the conversation with the system prompt.
        self.messages.append(
            {
                "role": "system",
                "content": build_system_prompt(self.user_id, self.role),
            }
        )


@dataclass
class AgentSession:
    """
    Per-user agent session.

    Holds the authenticated user identity, the conversation history, and
    the MCP client connection. One instance per user session.
    """

    user_id: str
    role: str
    mcp_url: str
    model: str = field(default_factory=lambda: os.environ.get("AGENT_MODEL", "gpt-4o"))
    messages: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        # Seed the conversation with the system prompt.
        self.messages.append(
            {
                "role": "system",
                "content": build_system_prompt(self.user_id, self.role),
            }
        )


def _mcp_tools_to_openai_format(mcp_tools: list[Any]) -> list[dict[str, Any]]:
    """
    Convert MCP tool definitions to OpenAI's function-calling schema.

    MCP describes tools with JSON Schema for inputs. OpenAI's `tools`
    parameter expects the same JSON Schema, wrapped in a specific
    envelope. This function is the translation.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.inputSchema or {"type": "object", "properties": {}},
            },
        }
        for t in mcp_tools
    ]


class Agent:
    """
    The unprotected ICARUS agent.

    Loop: ask LLM → if it requests tool calls, execute them → feed
    results back → repeat until LLM produces a text response or we hit
    MAX_TOOL_ITERATIONS.
    """

    def __init__(self, session: AgentSession):
        self.session = session
        self.llm = AsyncOpenAI()  # picks up OPENAI_API_KEY from env

    async def chat(self, user_message: str) -> str:
        """
        Process one user turn. Returns the assistant's final text reply.

        Mutates self.session.messages — the session's conversation
        history grows with each call.
        """
        self.session.messages.append({"role": "user", "content": user_message})

        async with MCPClient(self.session.mcp_url) as mcp:
            mcp_tools = await mcp.list_tools()
            openai_tools = _mcp_tools_to_openai_format(mcp_tools)

            for iteration in range(MAX_TOOL_ITERATIONS):
                response = await self.llm.chat.completions.create(
                    model=self.session.model,
                    messages=self.session.messages,
                    tools=openai_tools,
                    tool_choice="auto",
                )
                msg = response.choices[0].message

                # Append the assistant's message to history. Convert from
                # OpenAI's SDK object to a plain dict for stable storage.
                assistant_entry: dict[str, Any] = {
                    "role": "assistant",
                    "content": msg.content,
                }
                if msg.tool_calls:
                    assistant_entry["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in msg.tool_calls
                    ]
                self.session.messages.append(assistant_entry)

                # No tool calls? Then this is the final response.
                if not msg.tool_calls:
                    return msg.content or ""

                # Execute each tool call and append results.
                for tc in msg.tool_calls:
                    tool_name = tc.function.name
                    try:
                        tool_args = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        tool_args = {}

                    logger.info(
                        "Tool call: %s args=%s  [user=%s, iter=%d]",
                        tool_name,
                        tool_args,
                        self.session.user_id,
                        iteration,
                    )

                    try:
                        result = await mcp.call_tool(tool_name, tool_args)
                        # FastMCP returns a result object; extract the text payload.
                        result_text = result.content[0].text if result.content else ""
                    except Exception as e:
                        logger.exception("Tool call failed: %s", tool_name)
                        result_text = json.dumps({"error": str(e)})

                    self.session.messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id,
                            "content": result_text,
                        }
                    )

            # If we exit the loop without a final response, the LLM is stuck.
            logger.warning("Hit MAX_TOOL_ITERATIONS without final response")
            return "(agent exceeded max tool iterations)"

    # ─── CLI entrypoint ──────────────────────────────────────────────────────────


async def _interactive():
    """Tiny REPL for verifying Phase 3 works end-to-end."""
    import asyncio  # noqa
    from dotenv import load_dotenv
    from icarus.data.db_manager import verify_user

    load_dotenv()

    print("─── ICARUS agent (Phase 3 baseline, no guardrails) ───")
    user_id = input("user_id: ").strip()
    password = input("password: ").strip()

    user = verify_user(user_id, password)
    if user is None:
        print("Authentication failed.")
        return

    print(f"Logged in as {user['fullname']} (role: {user['role']})")
    print("Type your message. Ctrl+D or Ctrl+C to exit.\n")

    session = AgentSession(
        user_id=user["user_id"],
        role=user["role"],
        mcp_url=os.environ.get("VULNERABLE_MCP_URL", "http://127.0.0.1:9001/mcp"),
    )
    agent = Agent(session)

    while True:
        try:
            msg = input("you  > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nbye.")
            return
        if not msg:
            continue
        reply = await agent.chat(msg)
        print(f"bot  > {reply}\n")


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | agent | %(message)s",
    )
    asyncio.run(_interactive())
