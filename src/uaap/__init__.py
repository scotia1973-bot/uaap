"""Universal Agent Authorization Protocol (UAAP) — Python SDK

The trust layer for the AI agent economy.
"""

__version__ = "0.1.1"

from .agent_auth import AgentAuth, AgentIdentityToken, DelegationToken, Scope, Constraints
from .verifier import Verifier, VerificationResult
from .revocation import RevocationRegistry, DelegationChain

__all__ = [
    "AgentAuth",
    "AgentIdentityToken",
    "DelegationToken",
    "Verifier",
    "VerificationResult",
    "Scope",
    "ScopeAttenuation",
    "RevocationRegistry",
    "DelegationChain",
]
