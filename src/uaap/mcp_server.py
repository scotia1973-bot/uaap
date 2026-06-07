"""UAAP MCP Server — Authorization middleware for any MCP server.

Install: uvx uaap-mcp-server
Use: Wraps any MCP server with authorization verification.
"""

from mcp.server import Server
from mcp.server.stdio import stdio_server
import json
import httpx

from uaap.agent_auth import AgentAuth, Scope
from uaap.verifier import Verifier
from uaap.revocation import RevocationRegistry

# Initialize
auth = AgentAuth()
verifier = Verifier()
registry = RevocationRegistry()
server = Server("uaap-mcp-server")


@server.list_tools()
async def list_tools():
    return [
        {
            "name": "uaap_issue_identity",
            "description": "Issue a new agent identity token with cryptographic verification",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_name": {"type": "string", "description": "Name of the agent"},
                    "organization": {"type": "string", "description": "DID or domain of the organization"},
                    "capabilities": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["agent_name"],
            },
        },
        {
            "name": "uaap_delegate",
            "description": "Delegate authorization scope to a child agent with scope attenuation",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "subject": {"type": "string", "description": "DID of the child agent"},
                    "actions": {"type": "array", "items": {"type": "string"}},
                    "resources": {"type": "array", "items": {"type": "string"}},
                    "max_hops": {"type": "integer", "description": "Max delegation hops (1-5)"},
                },
                "required": ["subject"],
            },
        },
        {
            "name": "uaap_verify",
            "description": "Verify a delegation token against its issuer",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "delegation_id": {"type": "string"},
                    "issuer_url": {"type": "string"},
                },
                "required": ["delegation_id"],
            },
        },
        {
            "name": "uaap_check_intent",
            "description": "Verify a specific action is authorized before execution",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "delegation_id": {"type": "string"},
                    "action": {"type": "string"},
                    "resource": {"type": "string"},
                },
                "required": ["delegation_id", "action"],
            },
        },
        {
            "name": "uaap_revoke",
            "description": "Revoke a delegation token (invalidates all children)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "token_id": {"type": "string"},
                },
                "required": ["token_id"],
            },
        },
        {
            "name": "uaap_verify_chain",
            "description": "Verify an entire delegation chain for scope attenuation",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "chain_json": {"type": "string", "description": "JSON array of delegation tokens"},
                },
                "required": ["chain_json"],
            },
        },
        {
            "name": "uaap_wrap_mcp_tool",
            "description": "Wrap an MCP tool call with authorization check",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "delegation_id": {"type": "string"},
                    "tool_name": {"type": "string"},
                    "tool_args_json": {"type": "string"},
                },
                "required": ["delegation_id", "tool_name"],
            },
        },
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "uaap_issue_identity":
        token = auth.issue_identity(
            agent_name=arguments.get("agent_name", "agent"),
            organization=arguments.get("organization", "did:web:gadgethumans.com"),
            capabilities=arguments.get("capabilities"),
        )
        return {"content": [{"type": "text", "text": json.dumps(token.model_dump(), indent=2)}]}

    elif name == "uaap_delegate":
        scope = Scope(
            actions=arguments.get("actions", ["tools:execute"]),
            resources=arguments.get("resources", []),
            max_hops=arguments.get("max_hops", 3),
        )
        dt = auth.delegate(
            subject=arguments["subject"],
            scope=scope,
        )
        return {"content": [{"type": "text", "text": json.dumps(dt.model_dump(), indent=2)}]}

    elif name == "uaap_verify":
        dt_id = arguments["delegation_id"]
        url = arguments.get("issuer_url", "")
        result = verifier.verify_delegation(dt_id, url)
        return {"content": [{"type": "text", "text": json.dumps({
            "valid": result.valid,
            "notRevoked": result.not_revoked,
            "chain": result.chain,
            "error": result.error,
        }, indent=2)}]}

    elif name == "uaap_check_intent":
        authorized = verifier.verify_intent(
            delegation_id=arguments["delegation_id"],
            action=arguments["action"],
            resource=arguments.get("resource", ""),
        )
        return {"content": [{"type": "text", "text": json.dumps({
            "authorized": authorized,
            "action": arguments["action"],
        }, indent=2)}]}

    elif name == "uaap_revoke":
        registry.revoke(arguments["token_id"])
        return {"content": [{"type": "text", "text": json.dumps({
            "revoked": arguments["token_id"],
            "status": "ok",
        })}]}

    elif name == "uaap_verify_chain":
        from uaap.revocation import DelegationChain
        chain_data = json.loads(arguments["chain_json"])
        chain = DelegationChain()
        for t in chain_data:
            chain.add_token(t)
        valid, error = chain.verify()
        return {"content": [{"type": "text", "text": json.dumps({
            "valid": valid,
            "error": error,
        }, indent=2)}]}

    elif name == "uaap_wrap_mcp_tool":
        dt_id = arguments["delegation_id"]
        tool_name = arguments["tool_name"]

        # Verify authorization before execution
        authorized = verifier.verify_intent(
            delegation_id=dt_id,
            action=f"tools:{tool_name}",
            resource="*",
        )
        if not authorized:
            return {"content": [{"type": "text", "text": json.dumps({
                "error": f"Not authorized to execute {tool_name}",
                "authorized": False,
            })}]}

        return {"content": [{"type": "text", "text": json.dumps({
            "authorized": True,
            "tool": tool_name,
            "args": json.loads(arguments.get("tool_args_json", "{}")),
            "message": "Authorization verified. Tool execution permitted.",
        })}]}

    raise ValueError(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
