# FalkorTrace

**Graph-Guided Software Investigation, Sandboxed Verification & Version-Aware Agent Memory on FalkorDB**

[![Database](https://img.shields.io/badge/FalkorDB-v4.2.0_GraphBLAS-indigo)](https://www.falkordb.com/)
[![Backend](https://img.shields.io/badge/FastAPI-Python_3.11-009688)](https://fastapi.tiangolo.com/)
[![Protocol](https://img.shields.io/badge/MCP-12_Tools_(Model_Context_Protocol)-amber)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/Pytest-21%2F21_Passing-emerald)](./tests/test_falkortrace.py)
[![Live Demo](https://img.shields.io/badge/Live_Demo-Vercel_(ap--south--1)-success)](https://falkor-trace.vercel.app/)

---

## Core Thesis: Why Multi-Hop Graph Traversal + Sandboxed Verification + Version-Aware Memory Beats Single-Hop Retrieval

Why do standard **single-hop text retrieval** pipelines fail in production incident triage, and why is **FalkorDB** the core operational engine for reliable engineering agents?

When a customer files a ticket on an entrypoint service (e.g., `billing-edge-api`), single-hop text retrieval (`Lexical TF-IDF Baseline, k=3`) scores document chunks by lexical overlap. Because the ticket only mentions `billing-edge-api`, single-hop retrieval surfaces local chunks (`sim = 0.81`) and misses a breaking Git commit **3 hops downstream** in `proration-engine` (`sim = 0.14`, ranked #9)—or returns false nearest-neighbor matches when queried about an unknown service (`quantum-ledger-v9`).

Even more importantly, a production engineering agent **cannot rely on pre-seeded boolean graph flags** (`compliant: false`) or **blindly reuse stale past findings** when code artifacts change.

**FalkorTrace** places **FalkorDB at the center of a closed-loop verification architecture**:
1. **Left Pane (`❌ 1. Lexical TF-IDF Baseline (k=3)`)**: Computes deterministic TF-IDF Cosine Similarity over a **fair serialized fact corpus** (containing the exact same service, dependency, code module, commit, and PRD facts stored in FalkorDB), exposing single-hop retrieval blindness without handicapping the corpus.
2. **Center Hero Pane (`🧠 2. Core Central Unit: Live FalkorDB Graph Engine`)**: Traverses multi-hop dependencies (`[:DEPENDS_ON*1..4]`), native GraphBLAS algorithms (`algo.SPpaths`, `algo.pageRank`, `algo.WCC`, `algo.betweenness`), and selects allowlisted verification checks (`(:CheckDefinition)-[:VERIFIES]->(:Requirement)`). Supports a **controlled graph-only fault simulation** (`/api/inject-fault`) and **simulated artifact rollback** (`/api/remediate`); neither action changes an external deployment or incident system.
3. **Right Pane (`✅ 3. FalkorDB + Sandbox Verifier & Version-Aware Memory`)**: Executes deterministic sandboxed verification fixtures (`run_approved_check`) against the active `ArtifactVersion` (`sha:9f82d1a` vs `sha:7c31b09`), compares observed outputs against independent PRD specifications, and gates episodic memory reuse on a **Minimum Applicability Fingerprint** `(tenant_id, service, input_fingerprint, artifact_sha, req_version, check_version)`.

---

## Reproducible 12-Case 4-System Fixture Benchmark (`/api/benchmark`)

To isolate the contribution of **Multi-Hop Graph Traversal**, **Sandboxed Verification**, and **Version-Aware Memory**, FalkorTrace evaluates **4 Systems** across a frozen **12-case repository-fixture benchmark** (including 4-hop regressions, boundary proration cases, seat-discount rules, webhook payload errors, unknown services, isolated WCC islands, same-service multi-case memory safety, and post-remediation stale-version invalidation). Baseline scores are computed from the baseline's observable top-k output against an independently coded case oracle; they are not copied from the graph agent's verdict. This is a reproducible demo benchmark, not a held-out production evaluation: fixtures are repository-local, the baseline is lexical TF-IDF rather than vector-RAG, and latency is not a cold/warm/reuse performance study.

| System | Architecture | Verified Accuracy (12 Cases) | Key Finding |
| :--- | :--- | :--- | :--- |
| **System A** | `Lexical TF-IDF Chunk Baseline (k=3)` (Fair Serialized Fact Corpus, No Graph, No Verifier) | **33.3% (4/12)** | Retrieves local contract/payload text in some cases but misses the multi-hop regression and memory cases. |
| **System B** | `Local Retrieval + Verifier (Depth=1, No Multi-Hop Graph)` | **33.3% (4/12)** | Verifies local cases but cannot discover downstream roots or topology evidence. |
| **System C** | `FalkorDB Multi-Hop Graph + Sandbox Verifier (Stateless, Memory Disabled)` | **100.0% (12/12)** | Achieves 100% accuracy via multi-hop traversal + sandboxed check execution, but re-runs full traversal & verification on every repeat incident. |
| **System D** | `FalkorDB Multi-Hop Graph + Sandbox Verifier + Version-Aware Memory` | **100.0% (12/12)** | **100% accuracy + one avoided repeat check** on exact fingerprint match, **0% false reuse** on same-service different-input tickets, and **0% stale reuse** after artifact rollback. |

---

## 4 Deterministic Answer Shapes & Adjudicated Verdicts

Every investigation deterministically classifies the incident into one of **5 Answer Shapes** (`answered_with_path`, `answered_from_memory`, `not_in_the_graph`, `unknown_service`, `insufficient_evidence`):

| Verdict | Meaning | Graph Lineage & Sandboxed Verification Proof |
| :--- | :--- | :--- |
| **`PATCH_REGRESSION`** | A deployment modified a downstream module (up to 4 hops away) and failed its linked `CheckDefinition` against the independent PRD/SRD spec. | `(:Client_Issue)-[:REPORTS_ON]->(:Service)-[:DEPENDS_ON*1..4]->(:Service)-[:IMPLEMENTED_BY]->(:Code_Module)<-[:TARGETS]-(:CheckDefinition)-[:VERIFIES]->(:Requirement)` + `Observation(status='FAIL', expected='$30.00', observed='$45.00')` |
| **`WORKING_AS_PER_PRD`** | All candidate checks pass (`status='PASS'`); the client's expectation contradicts an explicit PRD/SRD contract threshold. | `(:Service)-[:IMPLEMENTED_BY]->(:Code_Module)<-[:TARGETS]-(:CheckDefinition)` + `Observation(status='PASS', expected='0% (<50 seats)', observed='0% (42 seats)')` |
| **`DATA_PAYLOAD_ISSUE`** | The client sent a malformed webhook/API payload (e.g., `"USDT-ERC20"` or invalid plan code) rejected by the validator check while service code is healthy. | `(:Client_Issue {payload_valid: false})` + `Observation(payload_schema_failed=True, check_id='CHK-WEBHOOK-ISO4217')` |
| **`UNMODELED_DEPENDENCY` / `UNMODELED_OR_UNKNOWN`** | The queried service either sits in an isolated WCC island (`not_in_the_graph`) or does not exist in the tenant graph (`unknown_service`). | Blocked at `resolve_service` Entity Resolution Gate or detected via `CALL algo.WCC(...)`. |
| **`INSUFFICIENT_EVIDENCE`** | The requested ticket is unknown or cross-service, the payload is malformed, or no graph-backed allowlisted check can execute. FalkorTrace abstains instead of fabricating a healthy or failing verdict. | No verification result is claimed; the response records the evidence boundary and the rejected input. |

---

## System Architecture

```text
+---------------------------------------------------------------------------------------------------+
|                        FALKORTRACE 3-PANE DARK-MODE OPERATIONS DASHBOARD                          |
|  [Left: Lexical TF-IDF (k=3)]   [Center: Live FalkorDB DAG & Cypher]   [Right: Sandbox & Memory]  |
+-------------------------------------------------+-------------------------------------------------+
                                                  | REST JSON (/api/triage, /api/benchmark, /api/ask)
                                                  v
+---------------------------------------------------------------------------------------------------+
|                             FASTAPI BACKEND & MCP SERVER (backend/)                               |
|                                                                                                   |
|  [Step 1: Entity Gate] ---> [Step 2: Version-Aware Memory Gate] ---> [Step 3: PRD & Ticket Scope] |
|   resolve_service()          evaluate_memory_applicability()          inspect_ticket_and_prd()    |
|          |                    - Exact Fingerprint -> REUSE                   |                    |
|          | (0 rows -> HALT:   - Diff Input -> HYPOTHESIS_ONLY                v                    |
|          |  unknown_service)  - Diff SHA -> INVALIDATED_STALE       [Step 4: Multi-Hop Narrowing] |
|                                                                      trace_blast_radius(*1..4)    |
|                                                                      inspect_recent_patches()     |
|                                                                      list_relevant_checks()       |
|                                                                              |                    |
|  [Entity-Ref Guardrail] <------------------------------------------- [Step 5: Sandbox Verifier]   |
|   accepts(sentence, answer)   <--- service_criticality_pagerank() <-- run_approved_check()        |
|   record_finding(fingerprint)      shortest_dependency_path(SPpaths)  (Compares independent spec  |
|                                    analyze_topology_islands(WCC)       vs observed code output)   |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                db.select_graph("falkortrace:killbill-prod") | db.select_graph("falkortrace:nexus-commerce")
                graph.ro_query(cypher, params) [Reads]       | graph.query(cypher, params) [Controlled Writes]
                                                  v
+---------------------------------------------------------------------------------------------------+
|                       FALKORDB MULTIGRAPH ENGINE (GraphBLAS Sparse Matrices)                      |
|   (:Client_Issue)-[:REPORTS_ON]->(:Service)-[:DEPENDS_ON*1..4]->(:Service)-[:IMPLEMENTED_BY]->    |
|   (:Code_Module)<-[:TARGETS]-(:CheckDefinition)-[:VERIFIES]->(:Requirement)<-[:REMEDIATES]-(:Runbook)
|   (:Observation)-[:OBSERVED_ON]->(:Code_Module) | (:Finding)-[:EVIDENCED_BY]->(:Observation)      |
+---------------------------------------------------------------------------------------------------+
```

---

## Core Engineering Guarantees

1. **Graph-Guided Sandboxed Verification (Zero Pre-Baked Answers):** Verdicts are never read from static boolean properties. FalkorDB narrows candidate services and selects allowlisted `CheckDefinition` nodes (`CHK-PRORATION-30-360`, `CHK-DISCOUNT-SEAT-50`, `CHK-WEBHOOK-ISO4217`, `CHK-TAX-ROUNDING`, `CHK-NEXUS-TTL`), which execute deterministic fixtures in [`backend/verifier.py`](./backend/verifier.py) against versioned code artifacts (`ArtifactVersion`) and compare observed outputs against an independent requirement specification table.
2. **Version-Aware Investigation Memory & Selective Invalidation:** Every `(:Finding)` and `(:Observation)` stores a **Minimum Applicability Fingerprint**: `(tenant_id, service, input_fingerprint, artifact_sha, req_version, check_version)`.
   - **Exact Match (`REUSE_APPLICABLE_OBSERVATION`):** Reuses the verified observation without re-running the sandbox; full request latency varies by deployment and network.
   - **Same Service, Different Input (`HYPOTHESIS_ONLY_DIFFERENT_INPUT`):** Refuses to blindly copy a prior verdict onto a different ticket/payload on the same service; runs fresh verification.
   - **Changed Artifact (`INVALIDATED_STALE_VERSION`):** When `/api/remediate` or `/api/inject-fault` updates `active_artifact_sha`, prior findings are marked `status = 'STALE_VERSION_MISMATCH'` (preserving full audit history in FalkorDB rather than deleting nodes) and fresh verification is forced.
3. **Zero LLM-Generated Cypher & Strict `ro_query()` Separation:** All graph reads execute through parameterized Cypher tools in [`backend/tools.py`](./backend/tools.py) via `graph.ro_query(cypher, params)`.
4. **Logical Multigraph Tenant Isolation:** Isolates tenant state via `db.select_graph(f"falkortrace:{tenant_id}")` with strict tenant allowlist validation (`validate_tenant_scope`).
5. **Explicit Engine Mode Telemetry (`LIVE_FALKORDB` vs `IN_MEMORY_FALLBACK`):** Reports live engine status in `/api/health` and UI badges, with `FALKORTRACE_STRICT_DB=1` support to disable fallback when strict live-DB testing is required.
6. **Entity-Reference Guardrail (`accepts()`):** [`accepts(sentence, answer)`](./backend/agent.py) verifies that every service and code module identifier in generated prose exists in FalkorDB's traversed result set (while behavioral truth is proven by the sandboxed `Observation` node).
7. **Protected Administration Surface:** Destructive actions and runtime configuration require `FALKORTRACE_ADMIN_TOKEN` when configured. The public dashboard can remain read-only while local development can omit the token.

---

## Graph Data Model (Cypher Schema)

### Nodes
- `(:Client_Issue {id, title, client_name, client_tier, reported_service, reported_payload, payload_valid, payload_error, expected_behavior, actual_behavior, created_at})`
- `(:Service {name, tier, language, repo, description})`
- `(:Code_Module {name, filepath, method_name, governed_field, logic_summary, active_artifact_sha, active_version_tag, code_hash})`
- `(:ArtifactVersion {id, module, service, version_tag, git_sha, code_hash, status})`
- `(:Requirement {id, doc_type, title, rule_text, version})` *(`PRD` or `SRD`)*
- `(:CheckDefinition {id, check_version, target_module, target_service, requirement_id, requirement_version, description})`
- `(:Observation {observation_id, tenant_id, service, run_id, check_id, check_version, case_id, target_module, target_service, requirement_id, requirement_version, artifact_sha, artifact_version, code_hash, input_fingerprint, expected_value, observed_value, status, violation_reproduced, at})`
- `(:Change {sha, patch_version, summary, diff_snippet, at, hours_ago, author})`
- `(:Team {name, slack_channel, pagerduty_schedule})`
- `(:Person {name, handle, email, role})`
- `(:Runbook {id, verdict_type, title, steps})` *(Procedural Memory)*
- `(:Finding {id, tenant_id, service, verdict, text, root_cause_node, ticket_id, input_fingerprint, artifact_sha, requirement_id, req_version, check_id, check_version, observation_id, run_id, validity_state, at, session})` *(Version-Aware Episodic Memory)*

### Relationships
```cypher
(issue:Client_Issue)-[:REPORTS_ON]->(s:Service)
(upstream:Service)-[:DEPENDS_ON {kind, weight, critical}]->(downstream:Service)
(s:Service)-[:IMPLEMENTED_BY]->(c:Code_Module)
(c:Code_Module)-[:IMPLEMENTS {note}]->(r:Requirement)
(c:Code_Module)-[:HAS_ARTIFACT {active}]->(av:ArtifactVersion)
(chk:CheckDefinition)-[:TARGETS]->(c:Code_Module)
(chk:CheckDefinition)-[:VERIFIES]->(r:Requirement)
(obs:Observation)-[:OBSERVED_ON]->(c:Code_Module)
(obs:Observation)-[:EXECUTED_CHECK]->(chk:CheckDefinition)
(obs:Observation)-[:TESTED_REQUIREMENT]->(r:Requirement)
(obs:Observation)-[:USED_ARTIFACT]->(av:ArtifactVersion)
(ch:Change)-[:MODIFIED]->(c:Code_Module)
(ch:Change)-[:DEPLOYED_TO]->(s:Service)
(t:Team)-[:OWNS]->(s:Service)
(p:Person)-[:MEMBER_OF]->(t:Team)
(p:Person)-[:ONCALL_FOR {from, to}]->(t:Team)
(p:Person)-[:WORKED_ON {commits}]->(s:Service)
(f:Finding)-[:ABOUT]->(s:Service)
(f:Finding)-[:EVIDENCED_BY]->(obs:Observation)
(rb:Runbook)-[:REMEDIATES]->(r:Requirement)
```

---

## Repository Structure

```text
FalkorTrace/
├── api/
│   └── index.py                     # ASGI Serverless Entrypoint
├── backend/
│   ├── __init__.py
│   ├── db.py                        # FalkorDB Cloud/Docker Manager + Strict Mode & Fallback
│   ├── verifier.py                  # Sandboxed Verification Runner + Applicability Fingerprints
│   ├── seed.py                      # Idempotent Multi-Tenant Graph Seeder (12-Case Suite)
│   ├── tools.py                     # 12 Parameterized Cypher, GraphBLAS & Verification Tools
│   ├── agent.py                     # Dynamic Graph-Guided Triage + accepts() Entity Guardrail
│   ├── mcp_server.py                # Model Context Protocol (MCP) Server (12 Tools)
│   └── main.py                      # FastAPI REST, 4-System Benchmark & MCP Application
├── frontend/
│   └── index.html                   # 3-Pane Interactive SVG DAG & Verification Operations UI
├── docs/
│   ├── ARCHITECTURE_AND_DESIGN.md   # System Architecture & Data Model Specification
│   ├── SRD.md                       # Software Requirements Document
│   └── FRD.md                       # Functional Requirements Document
├── tests/
│   └── test_falkortrace.py          # End-to-End Pytest Verification Suite (21 Tests)
├── Dockerfile
├── docker-compose.yml               # Pinned falkordb/falkordb:v4.2.0
├── Walkthrough.md                   # Complete functionality & 3–5 minute live demo script
├── vercel.json
├── Makefile                         # Reproducible test, compile, run, benchmark commands
├── requirements.lock                # Pinned Python dependency graph
├── .python-version                  # Python 3.11 runtime pin
└── requirements.txt
```

---

## Quickstart

### 1. Local Python + FalkorDB Cloud (or Local Docker)
```bash
# Install the pinned runtime dependencies
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.lock

# Configure FalkorDB connection (copy .env.example to .env)
cp .env.example .env

# Start FastAPI server (auto-verifies and seeds tenant graphs on startup)
make run
```
Open **http://localhost:8000**.

For a strict submission-style run, configure `FALKORTRACE_STRICT_DB=1`,
`FALKORTRACE_ADMIN_TOKEN`, and `FALKORTRACE_CORS_ORIGINS` in `.env`. The
dashboard keeps the admin token in memory only and sends it only to protected
routes. If live LLM prose is enabled, configure `GEMINI_API_KEY` or
`OPENAI_API_KEY` in the backend environment, plus optional
`FALKORTRACE_LLM_PROVIDER` and `FALKORTRACE_LLM_MODEL`. LLM credentials are
never entered or stored in the browser.

### 2. Docker Compose (Pinned `falkordb/falkordb:v4.2.0` + FalkorTrace App)
```bash
docker compose up --build
```

### 3. Run End-to-End Verification Suite
```bash
make test
```

### 4. Compile and benchmark smoke checks
```bash
make compile
make benchmark
```

See [`Walkthrough.md`](./Walkthrough.md) for the complete functionality checklist
and a timed 3–5 minute live demo script.

---

## REST & MCP API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | FalkorDB engine mode (`LIVE_FALKORDB` / `IN_MEMORY_FALLBACK`), active multigraphs, and MCP tool count (`12`) |
| `GET` | `/api/graph?tenant_id=killbill-prod` | Full node and directed edge topology (including `CheckDefinition`, `Observation`, `Finding`); `graph_source` identifies live FalkorDB reads versus the explicit fixture fallback |
| `POST` | `/api/triage` | Execute dynamic graph-guided triage + sandboxed verification for `(service, ticket_id, depth)` |
| `POST` | `/api/benchmark` | Run the reproducible **12-Case Fixture Benchmark** (Systems A, B, C, D); protected when an admin token is configured |
| `POST` | `/api/ask` | Natural-language question router (`"Why was ACME overcharged on TICKET-4902?"`) |
| `POST` | `/api/compare-depth` | Side-by-side comparison of shallow `depth=1` vs. multi-hop `depth=4` |
| `POST` | `/api/remediate` | Protected simulated artifact rollback: switches `active_artifact_sha`, marks prior findings `STALE_VERSION_MISMATCH`, and re-runs check |
| `POST` | `/api/inject-fault` | Protected controlled simulation: creates a faulty artifact version in the demo graph and invalidates prior findings; no external system is changed |
| `POST` | `/api/memory/clear` | Protected clear of `(:Finding)` and `(:Observation)` memory nodes for the active tenant |
| `POST` | `/api/seed` | Protected reset and re-seed of the specified tenant graph |
| `GET` | `/api/mcp/tools` | Model Context Protocol (MCP) tool definitions and JSON schemas (12 tools) |
| `POST` | `/api/mcp/call` | Execute any parameterized MCP tool directly; protected when an admin token is configured |

### Protected routes

When `FALKORTRACE_ADMIN_TOKEN` is non-empty, the following routes require either
`X-FalkorTrace-Admin-Token: <token>` or `Authorization: Bearer <token>`:

```text
/api/config/falkordb
/api/benchmark
/api/remediate
/api/inject-fault
/api/memory/clear
/api/seed
/api/mcp/call
```

The health endpoint never returns API-key previews or database passwords. LLM
credentials are backend-environment-only; the dashboard displays provider status
without exposing or accepting a key. Public deployments should also set
`FALKORTRACE_STRICT_DB=1` and an explicit `FALKORTRACE_CORS_ORIGINS` allowlist.

---

## WeMakeDevs × FalkorDB "Graph Hacks" Submission Details

### 1. Tracks Entered (All 3 Tracks)
- **Track 01 — Agents That Act on Connected Data:** Multi-hop causal reasoning (`*0..4`), graph queries and GraphBLAS algorithms exposed as **12 Model Context Protocol (MCP) tools**, sandboxed code verification (`run_approved_check`), and closed-loop artifact rollback (`/api/remediate`).
- **Track 02 — Agent Memory and Coordination:** Persistent episodic (`:Finding`), empirical (`:Observation`), semantic (`:Requirement`), and procedural (`:Runbook`) memory stored directly in FalkorDB, gated by a **Minimum Applicability Fingerprint** `(tenant_id, service, input_fingerprint, artifact_sha, req_version, check_version)` with isolated multigraphs per tenant (`falkortrace:killbill-prod`, `falkortrace:nexus-commerce`).
- **Track 03 — Company Brain:** Connects tickets (`:Client_Issue`), microservices (`:Service`), source files (`:Code_Module`), Git commits (`:Change`), PRD/SRD requirements (`:Requirement`), engineering teams (`:Team`), and on-call engineers (`:Person`) in a single traversable company knowledge graph.

### 2. Core Cypher Queries & GraphBLAS Algorithms Used
All production queries run against FalkorDB (`backend/tools.py`) using parameterized Cypher:
- **Multi-Hop Causal Blast-Radius Traversal (`trace_blast_radius`):**
  ```cypher
  MATCH path = (start:Service {name: $service})-[:ROUTES_TO*0..4]->(s:Service)
  OPTIONAL MATCH (s)-[:CONTAINS_CODE]->(c:Code_Module)
  OPTIONAL MATCH (c)-[gov:GOVERNED_BY]->(r:Requirement)
  OPTIONAL MATCH (c)-[:MODIFIED_BY]->(ch:Change)
  RETURN s.name AS service, length(path) AS hop_distance,
         c.name AS code_module, r.id AS req_id, gov.compliant AS compliant,
         ch.sha AS patch_sha, ch.summary AS patch_summary
  ORDER BY hop_distance ASC
  ```
- **Version-Aware Episodic Memory Lookup & Selective Invalidation (`evaluate_memory_applicability` / `remediate_regression`):**
  ```cypher
  MATCH (f:Finding)-[:ABOUT]->(s:Service {name: $service})
  OPTIONAL MATCH (f)-[:EVIDENCED_BY]->(obs:Observation)
  RETURN f, obs ORDER BY f.at DESC LIMIT 5
  ```
- **GraphBLAS Algorithms (`service_criticality_pagerank`, `shortest_dependency_path`, `analyze_topology_islands`):**
  - `CALL algo.pageRank('Service', 'ROUTES_TO')` — Ranks architectural blast-radius criticality across microservices.
  - `CALL algo.SPpaths({sourceNode: a, destNode: b, relTypes: ['ROUTES_TO']})` — Computes shortest causal dependency chains.
  - `CALL algo.WCC('Service', 'ROUTES_TO')` — Detects unmodeled or isolated topology islands.

### 3. AI Coding Assistant Disclosure
In compliance with Rule #11 of the WeMakeDevs Graph Hacks rules: AI coding assistants (Antigravity / Gemini) were used during the hackathon window to assist with boilerplate scaffolding, UI layout refinement, and test authoring, with all graph schema design, Cypher query logic, sandboxed verification architecture, and live FalkorDB Cloud verification directed and validated by the participant.

