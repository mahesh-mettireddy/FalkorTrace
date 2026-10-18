# FalkorTrace — Required Updates and Handoff

**Last checked:** 2026-10-17  
**Repository:** `FalkorTrace`  
**Branch:** `main`  
**Base revision when this handoff was written:** `7f9d80e`  
**Working-tree state:** The current implementation changes are present locally but are not committed.

## Local validation update (2026-10-18)

The following locally reproducible fixes are now included in the working tree:

- Verification rejects unknown services, tickets, artifacts, checks, cross-service ticket requests,
  malformed JSON, and non-UUIDv4 webhook idempotency keys instead of fabricating evidence.
- Triage abstains with `INSUFFICIENT_EVIDENCE` when no graph-backed allowlisted check can run.
- Dynamic fault simulation creates and links an `ArtifactVersion`; live and fallback memory clear
  both remove `Finding` and `Observation` nodes.
- `/api/graph` now serializes finding/observation provenance edges for checks, requirements,
  artifacts, and observations.
- Controlled remediation/fault-simulation wording is consistent in the dashboard and docs.
- `make test` now forces an isolated in-memory test database so an ignored `.env` cannot cause
  ordinary tests or benchmarks to mutate a shared FalkorDB instance.
- `.dockerignore` excludes local secrets, virtual environments, caches, logs, and audio artifacts;
  the repository now includes a CI workflow for compile/test/diff checks and Docker image build.
- The Starlette/httpx compatibility warning is resolved by pinning `httpx2` and its lockfile
  dependencies.

Observed local checks:

- `make test` — passed: 21 tests, no warnings.
- `make compile` — passed.
- Frontend inline JavaScript extraction followed by `node --check` — passed.
- `git diff --check` — passed.
- Fallback Uvicorn smoke: `/api/health`, `/`, `/api/graph`, and a three-hop triage request passed.
- Fallback benchmark: 12 cases; Systems A/B 33.3%, Systems C/D 100.0%.
- Admin-token Uvicorn smoke: `/api/benchmark` returned `401` without/with an invalid token and
  `200` with the configured demo token; the successful response contained 12 cases and 100% System D accuracy.
- Strict-mode startup correctly failed closed when no FalkorDB server was reachable.

Still blocked by this environment: Docker Compose build/runtime validation, browser walkthrough,
and public Vercel redeployment/live strict FalkorDB verification. These remain release-validation
items and must not be marked complete without external evidence.

## Local hosted scenario validation (2026-10-18)

The application is currently hosted locally at `http://127.0.0.1:8000` with an isolated fallback
database, a runtime-only admin token, and a local CORS allowlist. The tenant graph was reseeded
clean after the scenario run. Observed HTTP scenario results:

- Health and dashboard root — `200`; dashboard HTML served; engine reported `IN_MEMORY_FALLBACK`.
- MCP catalogue — `200`; 12 tools returned.
- Depth comparison — `200`; depth 1 returned `WORKING_AS_PER_PRD`, depth 4 found
  `PATCH_REGRESSION` at `proration-engine`.
- Three-hop regression — `PATCH_REGRESSION`, verification `FAIL`.
- Exact memory reuse — `answered_from_memory`, `REUSE_APPLICABLE_OBSERVATION`.
- Different-input protection — `HYPOTHESIS_ONLY_DIFFERENT_INPUT`, fresh verification `FAIL`.
- Unknown service — `unknown_service` / `UNMODELED_OR_UNKNOWN`.
- Isolated topology — `not_in_the_graph` / `UNMODELED_DEPENDENCY`.
- Unmapped invalid plan — `insufficient_evidence` / `INSUFFICIENT_EVIDENCE`.
- Controlled rollback — `200`, `SIMULATED_SANDBOX_ARTIFACT_ROLLBACK`; follow-up verification `PASS`.
- Controlled fault simulation — `200`, `SIMULATED_CHAOS_FAULT_INJECTION`; follow-up root cause was
  `tax-ledger-adapter` with verification `FAIL` and a created artifact SHA.
- Graph provenance — all six expected provenance edge labels were returned.
- Memory clear — `200`; findings and observations both returned to zero.
- Protected-route checks — missing token `401`, valid runtime token `200`.
- CORS checks — the configured local origin was allowed and an unrelated origin received no
  `access-control-allow-origin` header.

Cleanup completed: removed the audio-only `falkortrace_demo_walkthrough.wav` artifact and
regenerated Python/pytest caches. Required reproducibility files were retained.

This file records the remaining work needed to move the current local implementation from
“feature-complete and locally verified” to “release-validated and submission-ready.” Do not
claim the deployment, Docker runtime, or browser checks below as complete until their evidence
has been recorded.

## Current status

### Completed locally

- Backend security hardening: admin-token protection, restricted CORS support, secret redaction,
  strict database mode, and fail-closed graph operations.
- Provenance-aware, tenant-aware, version-aware observation and memory handling.
- Multi-hop graph traversal, check selection, sandbox verification, remediation, and fault-injection
  flows for the current controlled demo fixtures.
- Independent benchmark scoring for the frozen 12-case, four-system evaluation.
- Dashboard updates for live/fallback state, evidence paths, verification, memory decisions,
  ownership/actions, protected actions, loading/error/empty states, and accessibility basics.
- Reproducibility files: `.python-version`, `.dockerignore`, `Makefile`, pinned requirements,
  `requirements.lock`, `Dockerfile`, `docker-compose.yml`, and `.env.example`.
- Documentation updates in `README.md`, `Walkthrough.md`, `docs/SRD.md`, `docs/FRD.md`, and
  `docs/ARCHITECTURE_AND_DESIGN.md`.

### Evidence already obtained

- `make compile` — passed.
- `make test` — passed: 21 tests, with the Starlette/httpx compatibility warning removed.
- Frontend JavaScript syntax check — passed.
- `git diff --check` — passed.
- Isolated fallback fixture benchmark — Systems A/B: 4/12 (33.3%); Systems C/D: 12/12 (100.0%).
- Endpoint smoke checks — health, root, graph, triage, and protected-route behavior passed.

### Known constraints

- Docker is not installed in the current environment, so container build/runtime validation is
  still missing.
- No browser-level visual/manual review has been performed.
- The public Vercel deployment has not been redeployed and revalidated after the local changes.
- Benchmark fixtures are stored in the repository/demo data and are not genuinely held out.
- The benchmark baseline is lexical TF-IDF, not a production vector-RAG implementation.
- Verification, rollback, and chaos actions are controlled simulations rather than live GitHub,
  PagerDuty, or deployment integrations.

## Required updates

### P0 — Release and validation blockers

#### 1. Validate the Docker Compose path on a Docker-enabled machine

Run from the repository root:

```bash
docker compose config
docker compose build
docker compose up -d
make test
curl -fsS http://localhost:8000/api/health
curl -fsS -X POST http://localhost:8000/api/benchmark \
  -H "X-FalkorTrace-Admin-Token: <configured-demo-token>"
docker compose down
```

Record the observed results. Acceptance criteria:

- Compose configuration resolves without errors.
- The app image builds from the pinned lockfile and starts as a non-root user.
- Health reports `LIVE_FALKORDB` in strict mode.
- Benchmark and protected-route checks work with the configured token and fail with a missing/
  invalid token.
- `docker compose down` leaves no required state outside the project.

#### 2. Redeploy and validate the public environment

After the local/container checks pass, redeploy the Vercel application and verify:

- `FALKORTRACE_ADMIN_TOKEN` is configured in the deployment environment.
- `FALKORTRACE_STRICT_DB=1` is enabled for production.
- `FALKORTRACE_CORS_ORIGINS` contains only the intended dashboard origin(s).
- FalkorDB TLS settings, including `FALKORDB_SSL` and the connection credentials, are correct.
- `GET /api/health` reports `LIVE_FALKORDB`, not `IN_MEMORY_FALLBACK`.
- Protected routes return `401` without a token and succeed with the configured token.
- Health and LLM responses do not expose API-key previews, passwords, or tokens.

Do not put real credentials in this file, Git, screenshots, logs, or the README.

#### 3. Perform the browser walkthrough

Follow `Walkthrough.md` against the deployed app and record pass/fail results for:

- Initial loading, error, empty, degraded, and live states.
- Three-hop regression investigation and evidence path.
- Shallow versus multi-hop comparison.
- Exact memory reuse, different-input non-reuse, and stale-version invalidation.
- Unknown-service and isolated-topology abstention.
- Benchmark modal/cards and score initialization before/after loading.
- Admin-token entry, protected actions, token persistence only in the current tab, and logout/
  clear behavior.
- Keyboard focus, dialog Escape behavior, readable contrast, and responsive layout.

Fix any visual or interaction regression found before the final redeploy.

#### 4. Verify the live graph topology and provenance source

Confirm that `/api/graph` is populated from the intended live FalkorDB graph path rather than
only from a dataset snapshot or in-memory fallback. Verify that returned nodes and edges include
the expected artifact, observation, requirement, check, finding, and provenance relationships.
Document the result in the README or architecture document if the implementation differs from
the current description.

### P1 — Product completeness and credibility improvements

#### 5. Add durable coordination entities for Track 02

The current memory behavior is implemented, but the graph does not yet provide a complete durable
model for:

- `AgentRun`
- `Task`
- `Handoff`
- `Conversation`
- `ConversationTurn`

Add schemas, tenant-scoped persistence, retrieval, and API/MCP exposure. Add tests for ownership,
ordering, resumability, and cross-tenant isolation. Update `FRD.md`, `SRD.md`, and the dashboard
only after the entities are actually implemented.

#### 6. Complete the company-brain ingestion model for Track 03

Add real ingestion or clearly scoped adapters for the currently missing entities:

- `Document` and `DocumentChunk`
- `ChatMessage`, `Decision`, and `Source`
- `Repository`, `PullRequest`, and `Incident`

Each ingested record needs tenant identity, source/provenance, stable IDs, version or timestamp,
and relationships to the relevant service, requirement, artifact, finding, or handoff. Keep the
demo fixtures as fixtures; do not describe them as live integrations.

#### 7. Replace or explicitly isolate simulated operational actions

`/api/remediate` and `/api/inject-fault` currently model rollback and chaos behavior in a controlled
environment. Choose one of these paths:

1. Implement authenticated adapters for the target deployment, GitHub, and incident-management
   systems; or
2. Keep the simulation, but label it consistently in the UI, API documentation, README, and demo
   script as simulated and document the adapter boundary.

Add authorization, audit events, idempotency, and failure-path tests before calling any action
production-ready.

#### 8. Strengthen benchmark methodology

Keep the current benchmark as the reproducible demo benchmark, then add a separate evaluation
mode with:

- genuinely held-out cases or externally mounted fixtures,
- an independently versioned oracle,
- a documented split between development and evaluation data,
- repeated runs with variance reporting,
- latency measured separately for cold, warm, and memory-reuse paths, and
- explicit labels for lexical baseline versus vector retrieval if vector retrieval is added.

Update the benchmark claims in `README.md` and the design documents only after the new evidence is
available.

#### 9. Produce the actual demo artifact

Create a short screen-recorded demo if a video is required for submission. The current
`falkortrace_demo_walkthrough.wav` is audio only and must not be described as a video. Keep the
script in `Walkthrough.md` synchronized with the recorded flow.

### P2 — Maintenance and follow-up

#### 10. Remove the test-client deprecation warning

Track the Starlette/httpx compatibility warning from the current test suite. Upgrade or adjust
the test client once the supported dependency combination is available, then rerun the complete
test suite and keep the lockfile synchronized.

#### 11. Add repeatable CI checks

Add a repository-local CI workflow, if the target hosting environment supports it, that runs:

```bash
make compile
make test
git diff --check
```

Keep Docker build/compose checks in a separate job that has Docker available. Do not make a
network-dependent check the only required test path.

#### 12. Review and commit the current working tree

Before committing:

- inspect `git diff` and remove unrelated files or generated artifacts,
- decide whether `falkortrace_demo_walkthrough.wav` belongs in Git or should be stored elsewhere,
- verify that no `.env` file, credential, token, or private payload is included,
- stage only intended files, and
- use a conventional commit message for each logical change.

The current implementation is not merged or deployed merely because local checks passed.

## Final acceptance checklist

- [ ] Docker Compose config, build, startup, health, benchmark, and teardown verified.
- [ ] Browser walkthrough completed with no release-blocking issues.
- [ ] Public deployment redeployed and reports `LIVE_FALKORDB` in production.
- [ ] Production admin-token, strict DB, CORS, and TLS settings verified.
- [ ] `/api/graph` live-source and provenance behavior confirmed.
- [ ] Benchmark claims match the evidence and clearly disclose fixture limitations.
- [ ] Simulated actions are either integrated with real adapters or clearly labeled as simulations.
- [ ] Required demo video created, if submission rules require one.
- [ ] Test warning reviewed and dependencies/lockfile remain consistent.
- [ ] Working tree reviewed, secrets excluded, and intended changes committed.

## Next action

Start on a Docker-enabled machine with **P0.1**. Run the exact Compose validation commands above,
record the results here, then proceed to browser review and production redeployment. No item in the
final acceptance checklist should be marked complete without command output or a recorded manual
observation.
