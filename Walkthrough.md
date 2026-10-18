# FalkorTrace — 3–5 Minute Live Walkthrough

## What this demo proves

FalkorTrace is a graph-native incident investigation agent. It uses FalkorDB as the context and memory layer to:

1. Follow a customer issue across a multi-hop service graph.
2. Select and execute an allowlisted verification check against the active artifact version.
3. Reuse prior evidence only when the input, artifact, requirement, and check versions still match.
4. Resolve ownership, runbook guidance, and the next safe action.
5. Abstain when the requested entity is unknown or the topology is incomplete.

The dashboard maps directly to the three Graph Hacks tracks:

- **Track 01 — Connected-data action:** dependency traversal, Cypher, PageRank, WCC, MCP, and check selection.
- **Track 02 — Memory and coordination:** episodic findings, version-aware applicability, stale invalidation, and agent handoffs.
- **Track 03 — Company brain:** requirements, code artifacts, commits, runbooks, teams, on-call ownership, and evidence provenance.

## Before the demo

### Public deployment

Open the deployed dashboard and confirm the header shows:

- `LIVE_FALKORDB`
- the active graph scope, such as `falkortrace:killbill-prod`
- the strict database policy
- a non-error latency value

If the header shows `IN_MEMORY_FALLBACK`, explain that the demo is degraded and process-local. Do not claim a live FalkorDB result while fallback mode is active.

### Local deployment

```bash
cp .env.example .env
# Start FalkorDB and the app:
docker compose up --build
```

Open `http://localhost:8000`.

For a strict live-DB demo, set:

```bash
FALKORTRACE_STRICT_DB=1
FALKORTRACE_ADMIN_TOKEN=<demo-token>
FALKORTRACE_CORS_ORIGINS=http://localhost:8000
```

The admin token is needed only for protected actions such as benchmark execution, reset, memory clear, rollback, fault injection, and runtime configuration. The dashboard keeps it in memory for the current tab only.

If live LLM prose is enabled, set `GEMINI_API_KEY` or `OPENAI_API_KEY` in the
backend environment before starting the server. The dashboard intentionally has
no API-key input; it only reports whether the backend has a configured provider.

## 0:00–0:30 — Establish the problem

Say:

> A support ticket names the entrypoint service, but the real cause can be several dependency hops away. FalkorTrace does not ask an LLM to guess the join. FalkorDB supplies the connected path, the artifact version, the requirement, and the owner.

Point to the three track cards at the top of the dashboard:

- connected-data action
- version-aware memory
- company brain and provenance

Point out the engine badge. State whether the current session is using live FalkorDB or the explicit in-memory fallback.

## 0:30–1:20 — Track 01: find a three-hop regression

Select:

```text
1. 3-Hop Verifier — TICKET-4902
```

Keep the depth slider at `4` and click **Investigate** if necessary.

Explain the result:

```text
billing-edge-api
  -> subscription-service
  -> invoice-orchestrator
  -> proration-engine
```

The right-side evidence card should show:

- Verdict: `PATCH_REGRESSION`
- Check: `CHK-PRORATION-30-360`
- Artifact: faulty `sha:9f82d1a`
- Expected: `$30.00`
- Observed: `$45.00`
- Observation/run IDs
- requirement `PRD-INV-104`

Say:

> The verdict is not read from a seeded boolean. FalkorDB selected the candidate module and check; the sandbox executed the active artifact and compared it with the independent requirement specification.

Open the **Cypher & Checks** center tab. Show:

- `resolve_service`
- variable-length `DEPENDS_ON` traversal
- recent patch inspection
- `algo.SPpaths`
- PageRank/on-call resolution
- `run_approved_check`
- finding persistence

## 1:20–1:45 — Show the bounded-horizon safety behavior

Click **1 vs 4** or move the depth slider to `1` and investigate again.

Explain:

> At depth one, the agent does not claim the system is safe. It reports a shallow-horizon warning and tells the operator that deeper services remain uninspected. Increasing the horizon exposes the downstream regression.

This demonstrates safe abstention instead of false certainty.

## 1:45–2:25 — Track 02: prove version-aware memory

Select:

```text
6. Memory Reuse — Same Case (4902)
```

The memory card should show:

```text
REUSE_APPLICABLE_OBSERVATION
```

Point to the applicability fingerprint fields:

- tenant
- service scope
- input fingerprint
- artifact SHA
- requirement version
- check version

Say:

> This is not a generic semantic memory hit. The observation is reusable only because the complete applicability context still matches.

Now select:

```text
7. Memory Guard — Diff Case (4905)
```

Explain that the service is the same, but the input is different: Day 29 instead of Day 15. The agent must not blindly reuse the previous finding. It runs a fresh check and reports the new expected/observed values.

If time permits, use the protected rollback button. The rollback changes the active artifact, marks historical findings as stale, runs a clean verification, and re-runs the investigation.

## 2:25–3:05 — Track 03: contract, ownership, and provenance

Select:

```text
2. PRD Spec Check — TICKET-4908
```

Show:

- `WORKING_AS_PER_PRD`
- `CHK-DISCOUNT-SEAT-50`
- `PRD-DISC-209`
- expected 0% discount for 42 seats
- resolved Core Billing owner and runbook

Say:

> FalkorTrace can distinguish a software regression from a customer expectation that contradicts the contract. The evidence packet connects the ticket, service, module, requirement, check, observation, team, on-call engineer, and recommended action.

Point to the **Ownership + action card** and the runbook. Emphasize that the next action is routed from graph evidence rather than invented by the model.

## 3:05–3:35 — Show explicit evidence boundaries

Select:

```text
4. WCC Island — TICKET-4920
```

Explain:

> WCC finds that the service exists but is disconnected from the modeled billing topology. FalkorTrace reports insufficient evidence and asks for missing dependency data instead of claiming the service is healthy.

Then select:

```text
5. Unknown Entity — quantum-ledger-v9
```

Explain:

> The entity-resolution gate returns zero rows and stops the investigation before downstream traversal or verification. This prevents nearest-neighbor hallucination.

## 3:35–4:20 — Run the benchmark

Open **Run 12-Case Benchmark (A/B/C/D)**.

Before starting, say:

> The benchmark compares a text-only baseline, a local-verifier baseline, stateless graph verification, and graph verification with version-aware memory. The displayed numbers come from the benchmark response, not hardcoded UI labels.

If the backend requires authentication, enter the admin token in **Admin** first. The benchmark should display:

- System A accuracy
- System B accuracy
- System C accuracy
- System D accuracy
- latency
- per-case expected verdict and system results
- memory decision
- expected versus observed check output

Mention that System C and System D are evaluated against an independent case oracle. Avoid claiming “held-out” unless the submission data is actually separated from the training/demo fixtures.

## 4:20–4:50 — Optional controlled chaos simulation

Open **Simulate Fault**.

Choose `tax-ledger-adapter` and run the default simulated change.

Say:

> This is a controlled graph mutation. It creates a new change and artifact state, invalidates dependent memory, and lets the next investigation rediscover the changed root cause.

Run the investigation again and show the new check and observation.

Do not describe this as a production deployment. It is a sandboxed demonstration action.

## Closing statement

> FalkorTrace makes FalkorDB operationally central: the graph selects what to inspect, what to verify, what memory is applicable, who owns the result, and what action is safe. The verifier supplies executable proof, and the memory gate prevents stale conclusions after input or artifact changes.

## Full functionality checklist

The dashboard and API expose:

- Live FalkorDB health and explicit fallback status
- Tenant-scoped logical multigraphs
- Entity-resolution gate
- Natural-language question routing
- Depth-controlled multi-hop dependency traversal
- Shallow-versus-deep horizon comparison
- Recent patch and artifact inspection
- FalkorDB shortest path, PageRank, WCC, and betweenness tools
- Graph-selected allowlisted sandbox checks
- Observation persistence with artifact and requirement provenance
- Version-aware episodic memory
- Exact memory reuse
- Different-input memory rejection
- Stale-artifact invalidation after rollback/fault mutation
- Ownership and runbook routing
- Entity-reference guardrail
- MCP tool catalogue and invocation endpoint
- Four-system benchmark
- Protected reset, clear-memory, benchmark, rollback, fault-injection, and runtime configuration routes
- Tenant switching
- Accessible loading, empty, degraded, and error states

## After the demo

Run the reproducibility checks:

```bash
make compile
make test
git diff --check
```

For a deployment review, verify that:

- `FALKORTRACE_ADMIN_TOKEN` is configured.
- `FALKORTRACE_STRICT_DB=1` is configured.
- `FALKORTRACE_CORS_ORIGINS` contains only the real frontend origin.
- no credentials are committed in `.env` or source files.
- the dashboard reports `LIVE_FALKORDB` before making live-engine claims.
