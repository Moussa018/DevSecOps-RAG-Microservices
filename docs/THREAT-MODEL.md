# Threat model (STRIDE)

Scope: client → gateway → uaa / ingestion / rag / audit → qdrant, plus the call to the Anthropic API.
Risk = Damage + Reproducibility + Exploitability + Affected users + Discoverability, each 1-3 (DREAD, max 15).

| STRIDE | Threat | DREAD | Mitigation |
|---|---|---|---|
| **S**poofing | Forged or stolen JWT used on a service | 11 | RS256 pinned, issuer/audience/expiry checked, 2-min exchange tokens, one audience per token |
| **S**poofing | A pod pretends to be the gateway | 10 | Mutual TLS (private CA) + caller allow-list in the token (`act.sub`) |
| **T**ampering | Modified request between services | 8 | TLS on every hop |
| **T**ampering | Malicious document or prompt injection | 11 | Content check, masking, `<doc>` wrapping, injection guard |
| **R**epudiation | A user denies an upload or a query | 7 | `audit-service` records who did what (no question text) |
| **I**nformation disclosure | Reading another group's document | 12 | ACL filter built server-side from the signed `groups` claim |
| **I**nformation disclosure | Secrets or PII sent to the external API | 11 | Masking before indexing, output filter, single egress service |
| **D**enial of service | Login brute force, oversized uploads, API cost abuse | 9 | Login rate limit, size and chunk limits, Traefik body limit |
| **E**levation of privilege | Compromised pod moves sideways | 10 | Default-deny NetworkPolicy, no ingestion↔rag rule, non-root, read-only FS, `drop ALL` |
| **E**levation of privilege | Normal user calls admin routes | 9 | Role check at the gateway and again in each service |

Residual risks are listed in README section 8.
