# FalkorTrace

**Graph-Guided Software Investigation, Sandboxed Verification & Version-Aware Agent Memory on FalkorDB**

[![Database](https://img.shields.io/badge/FalkorDB-v4.2.0_GraphBLAS-indigo)](https://www.falkordb.com/)
[![Backend](https://img.shields.io/badge/FastAPI-Python_3.11-009688)](https://fastapi.tiangolo.com/)
[![Protocol](https://img.shields.io/badge/MCP-12_Tools_(Model_Context_Protocol)-amber)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/Pytest-10%2F10_Passing-emerald)](./tests/test_falkortrace.py)
[![Live Demo](https://img.shields.io/badge/Live_Demo-Vercel_(ap--south--1)-success)](https://falkor-trace.vercel.app/)

---

## Core Thesis: Why Multi-Hop Graph Traversal + Sandboxed Verification + Version-Aware Memory Beats Single-Hop Retrieval

Why do standard **single-hop text retrieval** pipelines fail in production incident triage, and why is **FalkorDB** the core operational engine for reliable engineering agents?

When a customer files a ticket on an entrypoint service (e.g., `billing-edge-api`), single-hop text retrieval (`Lexical TF-IDF Baseline, k=3`) scores document chunks by lexical overlap. Because the ticket only mentions `billing-edge-api`, single-hop retrieval surfaces local chunks (`sim = 0.81`) and misses a breaking Git commit **3 hops downstream** in `proration-engine` (`sim = 0.14`, ranked #9)—or returns false nearest-neighbor matches when queried about an unknown service (`quantum-ledger-v9`).

Even more importantly, a production engineering agent **cannot rely on pre-seeded boolean graph flags** (`compliant: false`) or **blindly reuse stale past findings** when code artifacts change.

**FalkorTrace** places **FalkorDB at the center of a closed-loop verification architecture**:
1. **Left Pane (`❌ 1. Lexical TF-IDF Baseline (k=3)`)**: Computes deterministic TF-IDF Cosine Similarity over a **fair serialized fact corpus** (containing the exact same service, dependency, code module, commit, and PRD facts stored in FalkorDB), exposing single-hop retrieval blindness without handicapping the corpus.
2. **Center Hero Pane (`🧠 2. Core Central Unit: Live FalkorDB Graph Engine`)**: Traverses multi-hop dependencies (`[:DEPENDS_ON*1..4]`), native GraphBLAS algorithms (`algo.SPpaths`, `algo.pageRank`, `algo.WCC`, `algo.betweenness`), and selects allowlisted verification checks (`(:CheckDefinition)-[:VERIFIES]->(:Requirement)`). Supports **Live Chaos Fault Injection** (`/api/inject-fault`) and **Simulated Artifact Rollback** (`/api/remediate`).
3. **Right Pane (`✅ 3. FalkorDB + Sandbox Verifier & Version-Aware Memory`)**: Executes deterministic sandboxed verification fixtures (`run_approved_check`) against the active `ArtifactVersion` (`sha:9f82d1a` vs `sha:7c31b09`), compares observed outputs against independent PRD specifications, and gates episodic memory reuse on a **Minimum Applicability Fingerprint** `(tenant_id, service, input_fingerprint, artifact_sha, req_version, check_version)`.

---

## Live 12-Case 4-System Ablation Benchmark (`/api/benchmark`)

To isolate the exact contribution of **Multi-Hop Graph Traversal**, **Sandboxed Verification**, and **Version-Aware Memory**, FalkorTrace evaluates **4 Systems** across **12 scenarios** (including 4-hop regressions, boundary proration cases, seat-discount rules, webhook payload errors, unknown services, isolated WCC islands, held-out tickets, same-service multi-case memory safety, and post-remediation stale-version invalidation):

| System | Architecture | Verified Accuracy (12 Cases) | Key Finding |
| :--- | :--- | :--- | :--- |
| **System A** | `Lexical TF-IDF Chunk Baseline (k=3)` (Fair Serialized Fact Corpus, No Graph, No Verifier) | **0.0% (0/12)** | Blind to 2–3 hop causal chains and lacks executable verification or entity gating. |
| **System B** | `Local Retrieval + Verifier (Depth=1, No Multi-Hop Graph)` | **50.0% (6/12)** | Verifies 0/1-hop local services (`TICKET-4908`, `TICKET-4915`), but misses all 3-hop `proration-engine` and `tax-ledger-adapter` regressions. |
| **System C** | `FalkorDB Multi-Hop Graph + Sandbox Verifier (Stateless, Memory Disabled)` | **100.0% (12/12)** | Achieves 100% accuracy via multi-hop traversal + sandboxed check execution, but re-runs full traversal & verification on every repeat incident. |
| **System D** | `FalkorDB Multi-Hop Graph + Sandbox Verifier + Version-Aware Memory` | **100.0% (12/12)** | **100% accuracy + `~1ms` O(1) reuse** on exact fingerprint match, **0% false reuse** on same-service different-input tickets, and **0% stale reuse** after artifact rollback. |

---

## 4 Deterministic Answer Shapes & Adjudicated Verdicts

Every investigation deterministically classifies the incident into one of **4 Answer Shapes** (`answered_with_path`, `answered_from_memory`, `not_in_the_graph`, `unknown_service`):

| Verdict | Meaning | Graph Lineage & Sandboxed Verification Proof |
| :--- | :--- | :--- |
| **`PATCH_REGRESSION`** | A deployment modified a downstream module (up to 4 hops away) and failed its linked `CheckDefinition` against the independent PRD/SRD spec. | `(:Client_Issue)-[:REPORTS_ON]->(:Service)-[:DEPENDS_ON*1..4]->(:Service)-[:IMPLEMENTED_BY]->(:Code_Module)<-[:TARGETS]-(:CheckDefinition)-[:VERIFIES]->(:Requirement)` + `Observation(status='FAIL', expected='$30.00', observed='$45.00')` |
| **`WORKING_AS_PER_PRD`** | All candidate checks pass (`status='PASS'`); the client's expectation contradicts an explicit PRD/SRD contract threshold. | `(:Service)-[:IMPLEMENTED_BY]->(:Code_Module)<-[:TARGETS]-(:CheckDefinition)` + `Observation(status='PASS', expected='0% (<50 seats)', observed='0% (42 seats)')` |
| **`DATA_PAYLOAD_ISSUE`** | The client sent a malformed webhook/API payload (e.g., `"USDT-ERC20"` or invalid plan code) rejected by the validator check while service code is healthy. | `(:Client_Issue {payload_valid: false})` + `Observation(payload_schema_failed=True, check_id='CHK-WEBHOOK-ISO4217')` |
| **`UNMODELED_DEPENDENCY` / `UNMODELED_OR_UNKNOWN`** | The queried service either sits in an isolated WCC island (`not_in_the_graph`) or does not exist in the tenant graph (`unknown_service`). | Blocked at `resolve_service` Entity Resolution Gate or detected via `CALL algo.WCC(...)`. |

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
   - **Exact Match (`REUSE_APPLICABLE_OBSERVATION`):** Reuses verified finding in `~1ms`.
   - **Same Service, Different Input (`HYPOTHESIS_ONLY_DIFFERENT_INPUT`):** Refuses to blindly copy a prior verdict onto a different ticket/payload on the same service; runs fresh verification.
   - **Changed Artifact (`INVALIDATED_STALE_VERSION`):** When `/api/remediate` or `/api/inject-fault` updates `active_artifact_sha`, prior findings are marked `status = 'STALE_VERSION_MISMATCH'` (preserving full audit history in FalkorDB rather than deleting nodes) and fresh verification is forced.
3. **Zero LLM-Generated Cypher & Strict `ro_query()` Separation:** All graph reads execute through parameterized Cypher tools in [`backend/tools.py`](./backend/tools.py) via `graph.ro_query(cypher, params)`.
4. **Logical Multigraph Tenant Isolation:** Isolates tenant state via `db.select_graph(f"falkortrace:{tenant_id}")` with strict tenant allowlist validation (`validate_tenant_scope`).
5. **Explicit Engine Mode Telemetry (`LIVE_FALKORDB` vs `IN_MEMORY_FALLBACK`):** Reports live engine status in `/api/health` and UI badges, with `FALKORTRACE_STRICT_DB=1` support to disable fallback when strict live-DB testing is required.
6. **Entity-Reference Guardrail (`accepts()`):** [`accepts(sentence, answer)`](./backend/agent.py) verifies that every service and code module identifier in generated prose exists in FalkorDB's traversed result set (while behavioral truth is proven by the sandboxed `Observation` node).

---

## Graph Data Model (Cypher Schema)

### Nodes
- `(:Client_Issue {id, title, client_name, client_tier, reported_service, reported_payload, payload_valid, payload_error, expected_behavior, actual_behavior, created_at})`
- `(:Service {name, tier, language, repo, description})`
- `(:Code_Module {name, filepath, method_name, governed_field, logic_summary, active_artifact_sha, active_version_tag, code_hash})`
- `(:ArtifactVersion {id, module, service, version_tag, git_sha, code_hash, status})`
- `(:Requirement {id, doc_type, title, rule_text, version})` *(`PRD` or `SRD`)*
- `(:CheckDefinition {id, check_version, target_module, target_service, requirement_id, requirement_version, description})`
- `(:Observation {id, run_id, check_id, check_version, case_id, target_module, target_service, requirement_id, requirement_version, artifact_sha, artifact_version, code_hash, input_fingerprint, expected_value, observed_value, status, violation_reproduced, at})`
- `(:Change {sha, patch_version, summary, diff_snippet, at, hours_ago, author})`
- `(:Team {name, slack_channel, pagerduty_schedule})`
- `(:Person {name, handle, email, role})`
- `(:Runbook {id, verdict_type, title, steps})` *(Procedural Memory)*
- `(:Finding {id, verdict, text, root_cause_node, ticket_id, input_fingerprint, artifact_sha, code_hash, req_version, check_id, check_version, observation_run_id, expected_value, observed_value, status, at, session})` *(Version-Aware Episodic Memory)*

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
│   └── test_falkortrace.py          # End-to-End Pytest Verification Suite (10 Tests)
├── Dockerfile
├── docker-compose.yml               # Pinned falkordb/falkordb:v4.2.0
├── vercel.json
└── requirements.txt
```

---

## Quickstart

### 1. Local Python + FalkorDB Cloud (or Local Docker)
```bash
# Install dependencies
pip install -r requirements.txt

# Configure FalkorDB connection (copy .env.example to .env)
cp .env.example .env

# Start FastAPI server (auto-verifies and seeds tenant graphs on startup)
uvicorn backend.main:app --reload --port 8000
```
Open **http://localhost:8000**.

### 2. Docker Compose (Pinned `falkordb/falkordb:v4.2.0` + FalkorTrace App)
```bash
docker compose up --build
```

### 3. Run End-to-End Verification Suite
```bash
python -m pytest -v
```

---

## REST & MCP API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | FalkorDB engine mode (`LIVE_FALKORDB` / `IN_MEMORY_FALLBACK`), active multigraphs, and MCP tool count (`12`) |
| `GET` | `/api/graph?tenant_id=killbill-prod` | Full node and directed edge topology (including `CheckDefinition`, `Observation`, `Finding`) |
| `POST` | `/api/triage` | Execute dynamic graph-guided triage + sandboxed verification for `(service, ticket_id, depth)` |
| `POST` | `/api/benchmark` | Run the live **12-Case 4-System Ablation Benchmark** (Systems A, B, C, D) |
| `POST` | `/api/ask` | Natural-language question router (`"Why was ACME overcharged on TICKET-4902?"`) |
| `POST` | `/api/compare-depth` | Side-by-side comparison of shallow `depth=1` vs. multi-hop `depth=4` |
| `POST` | `/api/remediate` | Simulated artifact rollback: switches `active_artifact_sha`, marks prior findings `STALE_VERSION_MISMATCH`, and re-runs check |
| `POST` | `/api/inject-fault` | Simulated chaos fault injection: deploys faulty artifact version to downstream service and invalidates prior findings |
| `POST` | `/api/memory/clear` | Clear `(:Finding)` and `(:Observation)` memory nodes for the active tenant |
| `POST` | `/api/seed` | Reset and re-seed the specified tenant graph |
| `GET` | `/api/mcp/tools` | Model Context Protocol (MCP) tool definitions and JSON schemas (12 tools) |
| `POST` | `/api/mcp/call` | Execute any parameterized MCP tool directly |
