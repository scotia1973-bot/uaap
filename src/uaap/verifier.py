"""Cross-domain delegation verification."""

import json
from dataclasses import dataclass
from typing import Optional
import httpx

from .agent_auth import Scope, DelegationToken, AgentIdentityToken


@dataclass
class VerificationResult:
    """Result of a delegation verification."""
    valid: bool
    chain: list[dict]
    effective_scope: Optional[Scope] = None
    not_revoked: bool = False
    error: Optional[str] = None


class Verifier:
    """Verifies delegation chains across domains."""

    def __init__(self, http_client: Optional[httpx.Client] = None):
        self._http = http_client or httpx.Client(timeout=10)

    def verify_delegation(
        self,
        delegation_id: str,
        issuer_well_known: str = "",
    ) -> VerificationResult:
        """Verify a delegation token against its issuer's verification endpoint."""
        if not issuer_well_known:
            return VerificationResult(
                valid=False,
                chain=[],
                error="No issuer well-known endpoint provided",
            )

        try:
            url = f"{issuer_well_known}/.well-known/uaap/verify"
            resp = self._http.post(
                url,
                json={"delegationId": delegation_id},
                timeout=10,
            )
            if resp.status_code != 200:
                return VerificationResult(
                    valid=False,
                    chain=[],
                    error=f"Verification request failed: {resp.status_code}",
                )

            data = resp.json()
            return VerificationResult(
                valid=data.get("valid", False),
                chain=data.get("chain", []),
                effective_scope=Scope(**data["effectiveScope"]) if "effectiveScope" in data else None,
                not_revoked=data.get("notRevoked", False),
            )

        except httpx.RequestError as e:
            return VerificationResult(
                valid=False,
                chain=[],
                error=f"Network error: {e}",
            )

    def verify_intent(
        self,
        delegation_id: str,
        action: str,
        resource: str,
        issuer_well_known: str = "",
    ) -> bool:
        """Verify that an action is authorized by the delegation."""
        if not issuer_well_known:
            return False

        try:
            url = f"{issuer_well_known}/.well-known/uaap/check-intent"
            resp = self._http.post(
                url,
                json={
                    "delegationId": delegation_id,
                    "intent": {"action": action, "resource": resource},
                },
                timeout=10,
            )
            return resp.status_code == 200 and resp.json().get("authorized", False)
        except Exception:
            return False

    def check_revocation(
        self,
        delegation_id: str,
        issuer_well_known: str = "",
    ) -> bool:
        """Check if a delegation has been revoked."""
        if not issuer_well_known:
            return False

        try:
            url = f"{issuer_well_known}/.well-known/uaap/revocations"
            resp = self._http.get(url, timeout=10)
            if resp.status_code != 200:
                return False
            data = resp.json()
            return delegation_id not in data.get("revokedTokens", [])
        except Exception:
            return False

    def verify_delegation_chain(
        self,
        chain: list[DelegationToken],
    ) -> VerificationResult:
        """Verify a chain of delegation tokens locally."""
        for i, token in enumerate(chain):
            # Check scope attenuation
            if i > 0:
                parent = chain[i - 1]
                if not token.scope.is_subset_of(parent.scope):
                    return VerificationResult(
                        valid=False,
                        chain=[t.model_dump() for t in chain],
                        error=f"Scope attenuation failed at hop {i}",
                    )

            # Check hop limit
            if token.scope.max_hops <= 0 and i < len(chain) - 1:
                return VerificationResult(
                    valid=False,
                    chain=[t.model_dump() for t in chain],
                    error=f"Max hops exceeded at token {token.delegation_id}",
                )

        return VerificationResult(
            valid=True,
            chain=[t.model_dump() for t in chain],
            effective_scope=chain[-1].scope if chain else None,
            not_revoked=True,
        )
