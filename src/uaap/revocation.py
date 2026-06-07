"""Revocation registry for UAAP delegation tokens."""

import json
import time
import fnmatch
from typing import Optional
from pathlib import Path


class RevocationRegistry:
    """Manages revocation of agent identity and delegation tokens."""

    def __init__(self, storage_path: Optional[str] = None):
        self._revoked: dict[str, float] = {}
        self._storage_path = storage_path
        if storage_path:
            self._load()

    def _load(self):
        path = Path(self._storage_path)
        if path.exists():
            data = json.loads(path.read_text())
            self._revoked = data.get("revoked", {})

    def _save(self):
        if self._storage_path:
            path = Path(self._storage_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"revoked": self._revoked}, indent=2))

    def revoke(self, token_id: str):
        """Revoke a token. All children are automatically invalidated."""
        self._revoked[token_id] = time.time()
        self._save()

    def is_revoked(self, token_id: str) -> bool:
        """Check if a specific token has been revoked."""
        return token_id in self._revoked

    def to_json(self) -> dict:
        """Export the registry as JSON (for the well-known endpoint)."""
        return {
            "revokedTokens": list(self._revoked.keys()),
            "revokedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "issuer": "did:web:gadgethumans.com",
            "totalRevoked": len(self._revoked),
        }


class DelegationChain:
    """Manages a chain of delegation tokens with scope attenuation verification."""

    def __init__(self):
        self._tokens: list[dict] = []

    def add_token(self, token: dict):
        self._tokens.append(token)

    def verify(self) -> tuple[bool, Optional[str]]:
        """Verify the entire chain for scope attenuation and limits."""
        for i, token in enumerate(self._tokens):
            scope = token.get("scope", {})
            if i > 0:
                parent = self._tokens[i - 1]
                parent_scope = parent.get("scope", {})

                # Check actions subset with wildcard support
                child_actions = set(scope.get("actions", []))
                parent_actions = set(parent_scope.get("actions", []))
                if child_actions and parent_actions:
                    for ca in child_actions:
                        if not any(fnmatch.fnmatch(ca, pa) for pa in parent_actions):
                            return False, f"Scope attenuation failed at hop {i}: '{ca}' not in parent scope"

                # Check resources subset with wildcard support
                child_res = set(scope.get("resources", []))
                parent_res = set(parent_scope.get("resources", []))
                if child_res and parent_res:
                    for cr in child_res:
                        if not any(fnmatch.fnmatch(cr, pr) for pr in parent_res):
                            return False, f"Scope attenuation failed at hop {i}: resource '{cr}' not in parent scope"

            # Check max hops
            max_hops = scope.get("max_hops", 3)
            remaining = max_hops - (len(self._tokens) - 1 - i)
            if remaining < 0:
                return False, f"Max hops exceeded at hop {i}"

        return True, None
