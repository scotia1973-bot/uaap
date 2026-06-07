# Universal Agent Authorization Protocol (UAAP) — Specification

## The SSL/TLS of the AI Agent Economy

**Version:** 0.1.0-draft
**Status:** DRAFT
**Author:** GadgetHumans

## Abstract

The AI agent economy cannot scale without a universal trust layer. Today, no mechanism exists for an agent in one organization to cryptographically verify the identity, authorization scope, or delegation chain of an agent in another organization. This spec defines a protocol for cross-domain agent authorization, delegation chains, scope attenuation, revocation propagation, and verifiable audit trails.

## 1. Core Concepts

### 1.1 Agent Identity Token (AIT)

A W3C Verifiable Credential (VC) containing:

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "AgentIdentityCredential"],
  "issuer": "did:web:gadgethumans.com",
  "credentialSubject": {
    "id": "did:uaap:agent:abc123",
    "agentName": "gadgethumans-api-hub-mcp",
    "agentType": "mcp-server",
    "capabilities": ["tools:execute", "tools:discover"],
    "organization": "did:web:gadgethumans.com",
    "publicKey": "did:key:z6Mk..."
  },
  "issuanceDate": "2026-06-07T00:00:00Z",
  "validUntil": "2027-06-07T00:00:00Z"
}
```

### 1.2 Delegation Token (DT)

A signed token that propagates authority across agents:

```json
{
  "delegationId": "dt_001",
  "issuer": "did:uaap:agent:parent-abc123"",
  "subject": "did:uaap:agent:child-def456",
  "scope": {
    "actions": ["tools:qr:generate", "tools:uuid:generate"],
    "resources": ["api.gadgethumans.com/*"],
    "maxHops": 2,
    "maxDepth": 3
  },
  "constraints": {
    "notBefore": "2026-06-07T00:00:00Z",
    "notAfter": "2026-06-08T00:00:00Z",
    "maxTokens": 1000000,
    "maxCostUSD": 5.00
  },
  "parentDelegationId": "dt_000",
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:uaap:agent:parent-abc123#key-1",
    "proofValue": "z..."
  }
}
```

### 1.3 Scope Attenuation Rule

**FUNDAMENTAL LAW:** Each delegation hop MUST narrow \( \subseteq \) the parent scope. Never expand.

```
scope(child) ⊆ scope(parent) for all properties:
  - actions ⊆ actions(parent)
  - resources ⊆ resources(parent)
  - maxHops ≤ maxHops(parent)
  - maxDepth ≤ maxDepth(parent)
```

### 1.4 Revocation

Each AIT/DT issuer maintains a **Revocation Registry** at a well-known URL:

```
https://gadgethumans.com/.well-known/uaap/revocations
```

Format:
```json
{
  "revokedTokens": ["dt_001", "dt_005", "ait_abc123"],
  "revokedAt": "2026-06-07T12:00:00Z",
  "issuer": "did:web:gadgethumans.com"
}
```

**Revocation Propagation Rule:** Revoking a parent token automatically invalidates ALL children in the delegation chain.

## 2. Protocol Flow

### 2.1 Delegation Request

```
Agent A (Org X) → Delegation Server (Org X):
  POST /.well-known/uaap/delegate
  {
    "subject": "did:uaap:agent:child-def456",
    "scope": { "actions": ["tools:*"], "maxHops": 1 },
    "parentDelegationId": "dt_000"
  }
```

### 2.2 Cross-Domain Verification

```
Agent B (Org Y) → Verification Server (Org X):
  GET /.well-known/uaap/verify?delegationId=dt_001
```

Response:
```json
{
  "valid": true,
  "chain": [
    { "id": "dt_000", "issuer": "did:web:org-x.com" },
    { "id": "dt_001", "issuer": "did:uaap:agent:parent-abc123" }
  ],
  "effectiveScope": {
    "actions": ["tools:*"],
    "remainingHops": 0
  },
  "notRevoked": true
}
```

### 2.3 Runtime Intent Verification

Before every tool execution:

```
Tool Runtime → Verification Server:
  POST /.well-known/uaap/check-intent
  {
    "delegationId": "dt_001",
    "intent": { "action": "tools:qr:generate", "resource": "api.gadgethumans.com/qr" }
  }
```

## 3. MCP Integration

### 3.1 UAAP Middleware for MCP

A transparent middleware layer that wraps any MCP server:

```
MCP Client → UAAP Middleware → MCP Server
              ↓
         Verification Check
```

### 3.2 MCP Tool Discovery with Authz

```json
{
  "tools": [{
    "name": "generate_qr",
    "uaap_required": ["tools:qr:generate"],
    "uaap_cost": 0.001
  }]
}
```

### 3.3 A2A Card Extension

```json
{
  "schema": "https://google.a2a/schemas/agent-card.json",
  "uaap": {
    "issuer": "did:web:gadgethumans.com",
    "verificationEndpoint": "https://api.gadgethumans.com/.well-known/uaap/verify",
    "delegationEndpoint": "https://api.gadgethumans.com/.well-known/uaap/delegate"
  }
}
```

## 4. Payment Integration (UAAP + x402)

### 4.1 Cost-Bound Delegation

Delegation tokens can include cost constraints:

```json
{
  "constraints": {
    "maxCostUSD": 5.00,
    "maxCostPerCall": 0.01,
    "paymentToken": "x402:0x..."
  }
}
```

### 4.2 Payment Verification

Before execution, verify that the caller has sufficient funds:

```
Check: remaining call cost ≤ maxCostPerCall?
       AND total cost ≤ maxCostUSD?
       AND wallet has sufficient balance?
```

## 5. Deployment

### 5.1 Well-Known Endpoints

All UAAP-compliant agents expose:

```
/.well-known/uaap/identity      — Agent Identity Token
/.well-known/uaap/delegate      — Delegation endpoint
/.well-known/uaap/verify        — Verification endpoint
/.well-known/uaap/revocations   — Revocation registry
/.well-known/uaap/check-intent  — Runtime intent check
```

### 5.2 Minimal Implementation (Python SDK)

```python
from uaap import AgentAuth, Delegation, Verifier

# Issue identity
auth = AgentAuth(key_material="...")
ait = auth.issue_identity(
    agent_name="my-agent",
    organization="did:web:myorg.com"
)

# Delegate
dt = auth.delegate(
    subject="did:uaap:agent:child-xyz",
    scope={"actions": ["tools:*"], "maxHops": 2}
)

# Verify (cross-domain)
verifier = Verifier()
result = verifier.verify_delegation("dt_001")
assert result.valid
assert "tools:qr:generate" in result.effective_scope.actions
```

## 6. Security Considerations

1. **Key Rotation:** Agents must support key rotation via DID document updates
2. **Revocation Timeliness:** Revocation registries should support Near-Real-Time updates (SSE/WebSocket push)
3. **Delegation Depth Limits:** Maximum 5 hops to prevent infinite delegation chains
4. **Scope Validation:** Servers MUST validate scope attenuation at each hop
5. **Audit Logging:** All delegation, verification, and intent checks MUST be logged

## 7. Appendix

### A. DID Methods

- `did:web` — For organizational identity
- `did:uaap` — For agent identity (UAAP-specific method)
- `did:key` — For in-protocol key material

### B. Integration with Existing Standards

| Standard | Integration Point |
|----------|------------------|
| MCP | UAAP middleware wraps MCP server |
| A2A | Agent card extension |
| x402 | Cost-bound delegation |
| OAuth 2.0 | Human-to-agent initial delegation |
| SPIFFE | Workload-level identity source |
| OpenFGA | Relationship-based policy engine |

---

**License:** MIT
**Repository:** github.com/scotia1973-bot/uaap
**MCP Server:** uvx uaap-mcp-server
