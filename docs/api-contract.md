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
| POST /workspaces/{ws}/action-requests | cicd:pipelines:execute | `{runId,type,reason}`; type from allowlist (`rerun_failed_jobs`); run must be failed; server computes risk (IMPLEMENTED) |
| GET /workspaces/{ws}/approvals | approvals:requests:read | IMPLEMENTED |
| POST /workspaces/{ws}/approvals/{id}/decision | approvals:requests:approve | approve/reject + reason; requester != approver; atomic single decision; approve runs the action inline (IMPLEMENTED) |
| GET /workspaces/{ws}/executions/{id} | auto:runbooks:read | backend-confirmed state only (IMPLEMENTED) |
| GET /audit-events | sec:telemetry:audit | filter + cursor pagination |
| GET /rbac/matrix | sys:rbac:read | |
| POST /webhooks/github | HMAC signature | not session-authenticated |

Permission strings reuse `ops-pilot-frontend/src/features/auth/permissions.ts` pending decision 3.

## Onboarding and membership (IMPLEMENTED, supersedes temp-password flow)
Flow: Platform Admin -> creates org + first-admin invitation link -> Org Admin creates workspaces and invites
people (org-wide or one workspace) -> Workspace Admin invites/manages inside their workspace only.
Invitation links are 256-bit, stored hashed, expire (invite 7d, reset 2h) and are single use. The token is shown
once to the inviter, who shares `/accept-invite?token=...` (email delivery is a later integration).

| Method + path | Who | Notes |
|---|---|---|
| POST /platform/organizations | Platform Admin | `{name,adminEmail}` -> org + default workspace + org_admin invitation |
| GET /platform/organizations | Platform Admin | counts only, no tenant data |
| POST /org/invitations | Org Admin | `{email,role,workspaceId?}`; workspace invites limited to workspace roles |
| GET/DELETE /org/invitations[/{id}] | Org Admin | pending list / revoke |
| POST /workspaces/{ws}/invitations | Workspace Admin+ | cannot grant own level or above |
| GET /invitations/{token} | public | preview (org, role, email) |
| POST /invitations/accept | public | `{token,name,password>=12}` creates account, or completes a password reset |
| POST /invitations/accept-existing | signed-in invitee | adds membership to an existing account |
| GET /org/members, GET/POST /org/workspaces | Org Admin | |
| PATCH/DELETE /org/memberships/{id} | Org Admin | not self; last org admin protected |
| DELETE /org/members/{userId} | Org Admin | disable account + end sessions |
| POST /org/members/{userId}/reset-link | Org Admin | single-use reset link |
| GET /workspaces/{ws}/members; PATCH/DELETE /workspaces/{ws}/memberships/{id} | Workspace Admin+ | scoped to the workspace |
| POST /auth/change-password | session | signs out other sessions |

Roles: platform admin (flag, tenant-blind), org_admin, workspace_admin, devops_engineer, developer, security_auditor, viewer.
Org-level endpoints only count org-wide memberships; workspace roles never grant org rights.

## GitHub integration, approvals and audit (IMPLEMENTED)
| Method + path | Who | Notes |
|---|---|---|
| GET/PUT/DELETE /workspaces/{ws}/integrations/github | `ws:integrations:manage` (org admin, workspace admin) | PUT `{repo, token?}`; token is write-only (Fernet at rest); GET returns `{connected, repo, tokenSet, lastSyncedAt}` |
| POST /workspaces/{ws}/integrations/github/test | same | `{ok}` or `{ok:false, reason: no_token|unauthorized|forbidden|repo_not_found_or_no_access|error}` |
| GET /workspaces/{ws}/approvals[?status=] | approvals read | rows include run context, requester, decision, execution |
| GET /audit-events?limit&action&outcome&before_id | audit read | actor name/email joined; `nextBefore` cursor; org-scoped |
| GET /workspaces/{ws}/overview | overview read | adds `approvals.pending`, `lastExecution` |

## Overview activity and automation history (IMPLEMENTED)
| Method + path | Who | Notes |
|---|---|---|
| GET /workspaces/{ws}/overview | overview read | now also `approvals.items` (needs approvals read), `recentExecutions` (needs automation read), `activity` (needs audit read) and `visible` flags; omitted sections are empty, never invented |
| GET /workspaces/{ws}/executions[?status=&limit=] | automation read | automation history: approved actions that executed, with run, decision and execution result |


## Google Cloud (read-only) (IMPLEMENTED)
| Method + path | Who | Notes |
|---|---|---|
| GET/PUT/DELETE /workspaces/{ws}/cloud/gcp | `cloud:connections:manage` (Organization Administrator only) | PUT `{key}` is a service-account JSON, write-only (Fernet at rest); GET returns `{connected, projectId, serviceAccount, keySet}` |
| POST /workspaces/{ws}/cloud/gcp/test | same | `{ok, project}` or `{ok:false, reason: unauthorized|forbidden|not_found|unreachable|error|...}` |
| GET /workspaces/{ws}/cloud/gcp/inventory | same | `{projectId, compute[], cloudRun[], gke[], errors{api: reason}}`; GET calls only, fixed Google hosts |

## Many repositories per workspace (IMPLEMENTED, supersedes the single `repo` field above)
A workspace has one GitHub connection holding an optional **shared token**, and up to 50 **repositories**. A repository
may carry its own token; otherwise it uses the shared one. Tokens are write-only (Fernet at rest).

| Method + path | Who | Notes |
|---|---|---|
| GET /workspaces/{ws}/integrations/github | `ws:integrations:manage` | `{connected, tokenSet, maxRepositories, lastSyncedAt, repositories:[{id, repo, ownToken, lastSyncedAt}]}` |
| PUT /workspaces/{ws}/integrations/github | same | `{token?, repo?}` sets the shared token and/or adds a repository |
| POST /workspaces/{ws}/integrations/github/repositories | same | `{repo, token?}`; adding an existing name is a no-op; 409 `too_many_repositories` past the limit |
| PUT /workspaces/{ws}/integrations/github/repositories/{id} | same | `{token}` sets its own token, or `{useSharedToken:true}` drops it |
| DELETE /workspaces/{ws}/integrations/github/repositories/{id} | same | stops tracking; synced runs stay as history |
| DELETE /workspaces/{ws}/integrations/github | same | removes every token and repository |
| POST /workspaces/{ws}/integrations/github/test | same | `{ok, results:[{repo, ok, reason?}], reason?}`, each repository tested with the token it really uses |
| GET /workspaces/{ws}/pipelines/runs[?repo=owner/name] | pipelines read | adds `repositories[]` |
| POST /workspaces/{ws}/pipelines/sync | pipelines execute | syncs every repository; `{synced, repositories, failed:[{repo, reason}]}`; one failure does not stop the others; 502/503 only when all fail |

Re-runs and log reads use the token of the run's own repository. The webhook updates every workspace tracking that repository.

## AI investigations (IMPLEMENTED, Groq)
Advisory only. The model never calls GitHub; it may suggest `rerun_failed_jobs` or `none`, and a suggestion becomes a
normal action request that a different person must approve.

| Method + path | Who | Notes |
|---|---|---|
| GET /workspaces/{ws}/investigations/status | `ai:copilot:use` | `{configured, provider, model}`; never the key |
| GET /workspaces/{ws}/investigations[?runId=&limit=] | same | newest first |
| POST /workspaces/{ws}/investigations | same | `{runId}`; failed runs only (409 `run_not_failed`); 5 per person per minute (429 `ai_rate_limited`); 503 `ai_not_configured`; 502 `ai_unauthorized`/`ai_model_unavailable`/`ai_unavailable`/`ai_bad_output`/`upstream_error` |

Pipeline: logs fetched with the repository's token -> secrets redacted -> trimmed to error lines plus context
(`OPSPILOT_AI_MAX_LOG_CHARS`, default 12000) -> sent to Groq inside untrusted-data markers -> output validated:
evidence quotes must appear in the log (others dropped, confidence lowered), action and confidence restricted to allowlists.
