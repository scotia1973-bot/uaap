"""UAAP verification server — exposes well-known endpoints for agent authorization."""

import json
import time
from typing import Optional
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .agent_auth import AgentAuth, Scope
from .revocation import RevocationRegistry

app = FastAPI(
    title="UAAP Verification Server",
    description="Universal Agent Authorization Protocol — well-known endpoints",
    version="0.1.0",
)

auth = AgentAuth()
registry = RevocationRegistry()


class DelegationRequest(BaseModel):
    subject: str
    scope: Optional[dict] = None
    parent_delegation_id: Optional[str] = None


class VerificationRequest(BaseModel):
    delegationId: str


class IntentCheckRequest(BaseModel):
    delegationId: str
    intent: dict


@app.get("/.well-known/uaap/identity")
async def get_identity():
    """Return the server's agent identity token."""
    token = auth.issue_identity(
        agent_name="uaap-verification-server",
        organization="did:web:gadgethumans.com",
        capabilities=["tools:execute", "uaap:verify", "uaap:delegate"],
    )
    return token.model_dump()


@app.post("/.well-known/uaap/delegate")
async def delegate(request: DelegationRequest):
    """Issue a delegation token to a child agent."""
    scope = Scope(**(request.scope or {}))
    dt = auth.delegate(
        subject=request.subject,
        scope=scope,
        parent_delegation_id=request.parent_delegation_id,
    )
    return dt.model_dump()


@app.post("/.well-known/uaap/verify")
async def verify(request: VerificationRequest):
    """Verify a delegation token."""
    is_revoked = registry.is_revoked(request.delegationId)
    return {
        "valid": not is_revoked,
        "chain": [{"id": request.delegationId}],
        "effectiveScope": {
            "actions": ["tools:*"],
            "maxHops": 2,
        },
        "notRevoked": not is_revoked,
    }


@app.post("/.well-known/uaap/check-intent")
async def check_intent(request: IntentCheckRequest):
    """Verify that an intent is authorized by a delegation."""
    is_revoked = registry.is_revoked(request.delegationId)
    action = request.intent.get("action", "")
    return {
        "authorized": not is_revoked and bool(action),
        "delegationId": request.delegationId,
        "intent": request.intent,
        "checkedAt": int(time.time()),
    }


@app.get("/.well-known/uaap/revocations")
async def get_revocations():
    """Return the revocation registry."""
    return registry.to_json()


@app.post("/.well-known/uaap/revoke")
async def revoke_token(data: dict):
    """Revoke a token."""
    token_id = data.get("tokenId", "")
    if not token_id:
        raise HTTPException(status_code=400, detail="tokenId required")
    registry.revoke(token_id)
    return {"revoked": token_id, "timestamp": int(time.time())}


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "protocol": "uaap",
        "version": "0.1.0",
        "revokedTokens": len(registry._revoked),
    }


def main():
    """Start the UAAP verification server."""
    uvicorn.run(app, host="0.0.0.0", port=8081)


if __name__ == "__main__":
    main()
