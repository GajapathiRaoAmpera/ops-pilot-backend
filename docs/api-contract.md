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

