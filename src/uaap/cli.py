"""UAAP CLI — Issue, verify, and manage agent delegations."""

import json
import sys
from .agent_auth import AgentAuth, Scope, Constraints
from .verifier import Verifier
from .revocation import RevocationRegistry


def main():
    if len(sys.argv) < 2:
        print("UAAP Protocol v0.1.0 — Universal Agent Authorization Protocol")
        print()
        print("Usage: uaap <command> [args]")
        print()
        print("Commands:")
        print("  issue-identity <name> <org>     Issue a new agent identity token")
        print("  delegate <subject>              Delegate scope to a child agent")
        print("  verify <delegation_id> <url>    Verify a delegation token")
        print("  revoke <token_id>               Revoke a token")
        print("  chain <file>                    Verify a delegation chain from JSON file")
        print("  server                          Start the UAAP verification server")
        return

    cmd = sys.argv[1]
    auth = AgentAuth()

    if cmd == "issue-identity":
        name = sys.argv[2] if len(sys.argv) > 2 else "my-agent"
        org = sys.argv[3] if len(sys.argv) > 3 else "did:web:gadgethumans.com"
        token = auth.issue_identity(agent_name=name, organization=org)
        print(json.dumps(token.model_dump(), indent=2))
        print(f"\nPrivate key (SAVE THIS): {auth.public_key_hex}")

    elif cmd == "delegate":
        subject = sys.argv[2] if len(sys.argv) > 2 else "did:uaap:agent:child-agent"
        scope = Scope(actions=["tools:execute"], max_hops=2)
        dt = auth.delegate(subject=subject, scope=scope)
        print(json.dumps(dt.model_dump(), indent=2))

    elif cmd == "verify":
        dt_id = sys.argv[2] if len(sys.argv) > 2 else ""
        url = sys.argv[3] if len(sys.argv) > 3 else ""
        verifier = Verifier()
        result = verifier.verify_delegation(dt_id, url)
        print(json.dumps({
            "valid": result.valid,
            "chain": result.chain,
            "error": result.error,
        }, indent=2))

    elif cmd == "revoke":
        token_id = sys.argv[2] if len(sys.argv) > 2 else ""
        registry = RevocationRegistry()
        registry.revoke(token_id)
        print(f"Revoked: {token_id}")

    elif cmd == "chain":
        path = sys.argv[2] if len(sys.argv) > 2 else ""
        with open(path) as f:
            tokens = json.load(f)
        from .revocation import DelegationChain
        chain = DelegationChain()
        for t in tokens:
            chain.add_token(t)
        valid, error = chain.verify()
        print(f"Chain valid: {valid}")
        if error:
            print(f"Error: {error}")

    elif cmd == "server":
        from .server import main as server_main
        server_main()

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
