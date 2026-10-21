# OpsPilot Threat Model (Phase 1 draft)

Status: PROPOSED. Nothing here is implemented yet.

## Assets
Session cookies, GitHub App private key / installation tokens, tenant data (runs, logs), approval decisions, audit trail, LLM prompts/outputs.

## Trust boundaries
Browser -> Next.js (relay) -> FastAPI -> Postgres / Worker -> GitHub / LLM API.
The browser never calls FastAPI directly. Webhooks from GitHub enter via `POST /webhooks/github` only.

## Threats and controls
| ID | Threat | Control | Test |
|---|---|---|---|
| T1 | Cross-tenant data access (IDOR) | Every query filtered by org/workspace from membership; cross-tenant returns 404 | Authz matrix: each route x role x tenant |
| T2 | Privilege escalation via client-supplied role/tenant | Role and tenant derived from session server-side only | Tamper tests on headers/body/query |
| T3 | Credential stuffing / brute force | argon2id, rate limit + lockout, generic errors | Rate-limit test |
| T4 | Session theft / CSRF | HttpOnly+Secure+SameSite cookie, CSRF token on unsafe methods, server-side revocation | CSRF test |
| T5 | Prompt injection via logs/repo content | Untrusted-content delimiting + sanitizer; LLM has no write tools; actions only via approval-gated allowlist | Injection corpus eval |
| T6 | Unapproved/forged write action | Execution requires an approval row; requester != approver enforced in service and DB constraint | SoD + bypass tests |
| T7 | Duplicate execution | Unique idempotency key on executions | Concurrency test |
| T8 | Secret leakage (logs, FE, LLM) | Secrets by reference only; log redaction; scrub before LLM | Redaction tests, gitleaks |
| T9 | Webhook spoofing | HMAC signature verification, replay window | Signature tests |
| T10 | Audit tampering | Append-only table (no UPDATE/DELETE grants), payload hash | Permission test |
| T11 | SSRF / command injection in adapters | Fixed API hosts, Pydantic-validated params, no shell | Param fuzz tests |
| T12 | Resource exhaustion | Timeouts, bounded retries, token/step budgets, pagination | Limit tests |

## Open items
Whether log content may be sent to an external LLM (decision 5), data retention periods, break-glass policy for Platform Admin.
