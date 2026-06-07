"""Agent identity and delegation token implementation."""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import BaseModel, Field


class Scope(BaseModel):
    """Authorization scope for delegation tokens."""
    actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    max_hops: int = Field(default=3, ge=0, le=5)
    max_depth: int = Field(default=5, ge=1, le=10)

    def is_subset_of(self, parent: "Scope") -> bool:
        """Verify scope attenuation: child scope must be subset of parent."""
        child_actions = set(self.actions)
        parent_actions = set(parent.actions)
        if not child_actions.issubset(parent_actions):
            return False
        child_resources = set(self.resources)
        parent_resources = set(parent.resources)
        if not child_resources.issubset(parent_resources):
            return False
        if self.max_hops > parent.max_hops:
            return False
        if self.max_depth > parent.max_depth:
            return False
        return True


class Constraints(BaseModel):
    """Time and cost constraints on a delegation."""
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    max_tokens: Optional[int] = None
    max_cost_usd: Optional[float] = None
    max_cost_per_call: Optional[float] = None


class AgentIdentityToken(BaseModel):
    """Cryptographically verifiable agent identity."""
    id: str
    agent_name: str
    agent_type: str = "mcp-server"
    capabilities: list[str] = Field(default_factory=list)
    organization: str
    public_key: str
    issued_at: str = ""
    valid_until: str = ""
    proof: Optional[dict] = None


class DelegationToken(BaseModel):
    """Signed token propagating authority across agents."""
    delegation_id: str
    issuer: str
    subject: str
    scope: Scope = Field(default_factory=Scope)
    constraints: Constraints = Field(default_factory=Constraints)
    parent_delegation_id: Optional[str] = None
    proof: Optional[dict] = None


class AgentAuth:
    """Central class for issuing agent identities and delegations."""

    def __init__(self, key_material: Optional[str] = None):
        if key_material:
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(key_material)
            )
        else:
            self._private_key = ed25519.Ed25519PrivateKey.generate()

        self._public_key = self._private_key.public_key()
        self._key_id = f"key-{int(time.time())}"

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def public_key_hex(self) -> str:
        return self.public_key_bytes.hex()

    def issue_identity(
        self,
        agent_name: str,
        organization: str,
        capabilities: Optional[list[str]] = None,
        valid_days: int = 365,
    ) -> AgentIdentityToken:
        """Issue a new agent identity token."""
        agent_id = f"did:uaap:agent:{agent_name}-{int(time.time())}"
        now = time.time()
        token = AgentIdentityToken(
            id=agent_id,
            agent_name=agent_name,
            agent_type="mcp-server",
            capabilities=capabilities or ["tools:execute"],
            organization=organization,
            public_key=self.public_key_hex,
            issued_at=f"{int(now)}",
            valid_until=f"{int(now + valid_days * 86400)}",
        )
        # Sign the token
        payload = token.model_dump_json().encode()
        signature = self._private_key.sign(payload)
        token.proof = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"{organization}#{self._key_id}",
            "proofValue": signature.hex(),
        }
        return token

    def delegate(
        self,
        subject: str,
        scope: Scope,
        constraints: Optional[Constraints] = None,
        parent_delegation_id: Optional[str] = None,
    ) -> DelegationToken:
        """Issue a delegation token to a child agent."""
        dt_id = f"dt_{int(time.time())}_{subject[-8:]}"
        token = DelegationToken(
            delegation_id=dt_id,
            issuer=f"did:uaap:agent:issuer-{int(time.time())}",
            subject=subject,
            scope=scope,
            constraints=constraints or Constraints(),
            parent_delegation_id=parent_delegation_id,
        )
        payload = token.model_dump_json().encode()
        signature = self._private_key.sign(payload)
        token.proof = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"did:uaap:agent:issuer#key-1",
            "proofValue": signature.hex(),
        }
        return token

    def verify_signature(self, payload: dict, signature_hex: str, public_key_hex: str) -> bool:
        """Verify a signature against a public key."""
        try:
            public_bytes = bytes.fromhex(public_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, json.dumps(payload, sort_keys=True).encode())
            return True
        except Exception:
            return False
