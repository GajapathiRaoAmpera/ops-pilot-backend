# OpsPilot API Contract (Phase 1 draft, PROPOSED, UNIMPLEMENTED)

To be converted to a machine-readable OpenAPI 3.1 spec (generated from FastAPI, reviewed before the frontend adapts).
Conventions: JSON; cookie session; `X-CSRF-Token` on unsafe methods; errors `{error:{code,message,request_id}}`;
401 unauthenticated, 403 lacking permission within a visible scope, 404 for out-of-scope resources.

| Method + path | Permission (proposed) | Notes |
|---|---|---|
| POST /auth/login | none | `{email,password}`; sets cookie; rate limited |
| GET /auth/me | session | `{user, organization, workspaces:[{id,name,role}], permissions[]}` (extends current frontend contract) |
| POST /auth/logout | session | revokes session |
| GET /workspaces/{ws}/overview | sys:overview:read | pipeline tiles + freshness; unconnected tiles flagged |
| GET /workspaces/{ws}/pipelines/runs | cicd:pipelines:read | paginated, filterable |
| GET /workspaces/{ws}/pipelines/runs/{id} | cicd:pipelines:read | |
| GET /workspaces/{ws}/pipelines/runs/{id}/logs | cicd:pipelines:read | sanitized |
| POST /workspaces/{ws}/investigations | ai:copilot:use | `{run_id}`; idempotent; async |
| GET /investigations/{id} | ai:copilot:use | diagnosis, evidence, confidence, tool trace |
| POST /action-requests | cicd:pipelines:execute | type from allowlist (`rerun_failed_jobs`); server computes risk |
| GET /approvals | approvals:requests:read | |
| POST /approvals/{id}/decision | approvals:requests:approve | approve/reject + reason; SoD enforced |
| GET /executions/{id} | auto:runbooks:read | backend-confirmed state only |
| GET /audit-events | sec:telemetry:audit | filter + cursor pagination |
| GET /rbac/matrix | sys:rbac:read | |
| POST /webhooks/github | HMAC signature | not session-authenticated |

Permission strings reuse `ops-pilot-frontend/src/features/auth/permissions.ts` pending decision 3.
