# Functional Requirements Document (FRD) — FalkorTrace

**Document ID:** `FRD-FALKORTRACE-2026-V2`  
**Project:** FalkorTrace — Graph-Guided Software Investigation, Sandboxed Verification & Version-Aware Agent Memory  

---

## 1. Functional Overview & Track Mapping

FalkorTrace fulfills functional requirements across all three hackathon tracks simultaneously:
- **Track 01 (Agents That Act on Connected Data):** `FR-T1-01` through `FR-T1-06`
- **Track 02 (Agent Memory & Coordination):** `FR-T2-01` through `FR-T2-05`
- **Track 03 (Company Brain):** `FR-T3-01` through `FR-T3-04`
- **3-Pane Operations UI & 12-Case Benchmark:** `FR-UI-01` through `FR-UI-07`

---

## 2. Detailed Functional Requirements

### 2.1 Entity Resolution, Graph-Guided Narrowing & Sandboxed Verification (`FR-T1`)

- **`FR-T1-01` (Entity Resolution Gate):**
  - *Input:* `service: str`
  - *Behavior:* Executes `MATCH (s:Service {name: $name}) RETURN s.name AS name, s.tier AS tier, s.description AS description` via `graph.ro_query()`.
  - *Output:* If empty, immediately halts the agent loop and returns `outcome = "unknown_service"` with `0` downstream queries and `0` check executions.

- **`FR-T1-02` (Depth-Controlled Blast Radius Traversal & Horizon Warning):**
  - *Input:* `service: str`, `depth: int (1..4)`
  - *Behavior:* Traverses `(s:Service {name: $service})-[:DEPENDS_ON*1..4]->(dep:Service)` with `WHERE length(path) <= $depth` and returns `dep.name`, `dep.tier`, `length(path) AS hops`, and `[n IN nodes(path) | n.name] AS via`.
  - *Bounded Horizon Policy:* When `depth < 4` leaves deeper downstream services uninspected, FalkorTrace flags `truncation_warning = True` and adds an explicit `unresolved_questions` item rather than claiming deeper hops are safe.

- **`FR-T1-03` (Multi-Hop Patch & Check Selection via FalkorDB):**
  - *Input:* `service: str`, `depth: int (1..4)`, `hours: int (default 72)`
  - *Behavior:* Traverses up to `$depth` hops downstream from `$service`, matching `(dep:Service)-[:IMPLEMENTED_BY]->(c:Code_Module)<-[:MODIFIED]-(ch:Change)` and querying `list_relevant_checks(service, module)` to discover allowlisted `(:CheckDefinition)` nodes (`CHK-PRORATION-30-360`, `CHK-DISCOUNT-SEAT-50`, `CHK-WEBHOOK-ISO4217`, `CHK-TAX-ROUNDING`, `CHK-NEXUS-TTL`).

- **`FR-T1-04` (Deterministic Sandboxed Verification Loop):**
  - *Input:* `check_id: str`, `case_id: str`, `artifact_sha: str`, `raw_payload: str`
  - *Behavior:* Executes `run_approved_check` (`execute_sandboxed_Verification_check` in `backend/verifier.py`) against the active `ArtifactVersion` (`9f82d1a` vs `7c31b09`, `88d12f0` vs `55a19c2`, etc.), compares the observed output against an independent requirement specification table (`INDEPENDENT_REQUIREMENT_SPECIFICATIONS`), and writes an `(:Observation)` node with `run_id`, `expected_value`, `observed_value`, and `status` (`PASS` / `FAIL`).

- **`FR-T1-05` (Native FalkorDB Graph Algorithms as Tools):**
  - **Shortest Dependency Path (`shortest_dependency_path`):** Executes `CALL algo.SPpaths({sourceNode: a, targetNode: b, relTypes: ['DEPENDS_ON'], relDirection: 'outgoing', weightProp: 'weight', pathCount: 1}) YIELD path, pathWeight`.
  - **Service Criticality & Oncall Escalation (`service_criticality_pagerank`):** Executes `CALL algo.pageRank('Service', 'DEPENDS_ON') YIELD node, score` and joins `(p:Person)-[:ONCALL_FOR]->(t:Team)-[:OWNS]->(s:Service)` plus `(expert:Person)-[w:WORKED_ON]->(s:Service)`.
  - **Topology Island & Chokepoint Detection (`analyze_topology_islands_and_bridges`):** Executes `CALL algo.WCC` and `CALL algo.betweenness` to identify isolated services (powering `not_in_the_graph`) and bridge bottlenecks.

- **`FR-T1-06` (Simulated Artifact Rollback & Controlled Chaos Fault Simulation):**
  - *Input:* `tenant_id: str`, `service: str`, `sha: str`
  - *Behavior:* `/api/remediate` switches `c.active_artifact_sha` to the clean revision (`7c31b09` / `55a19c2`), marks dependent `(:Finding)` nodes as `validity_state = 'STALE_VERSION_MISMATCH'` (preserving full historical audit trails), and runs `run_approved_check` to prove recovery (`expected == observed`).
  - `/api/inject-fault` is the corresponding controlled graph-only simulation: it creates a faulty `ArtifactVersion`, invalidates stale memory, and changes no external deployment or incident-management system.

---

### 2.2 Version-Aware Investigation Memory & Coordination (`FR-T2`)

- **`FR-T2-01` (Minimum Applicability Fingerprint Gate):**
  - Every `(:Finding)` and `(:Observation)` is stamped with `(tenant_id, service, input_fingerprint, artifact_sha, req_version, check_version)`.
  - `evaluate_memory_applicability` enforces four deterministic decisions:
    1. `REUSE_APPLICABLE_OBSERVATION`: Exact match on the complete applicability fingerprint $\rightarrow$ returns `answered_from_memory` without re-running the sandbox; request latency is deployment-dependent.
    2. `HYPOTHESIS_ONLY_DIFFERENT_INPUT`: Same service and valid code version, but different supported ticket input parameters (for example `TICKET-4905` Day 29) $\rightarrow$ refuses blind reuse and runs verification for the current inputs.
    3. `INVALIDATED_STALE_VERSION`: Stored finding's `artifact_sha` was superseded by a rollback or chaos deployment $\rightarrow$ rejects stale memory and re-runs verification.
    4. `INSUFFICIENT_EVIDENCE`: Unknown/cross-service tickets, malformed payloads, or reachable graph paths without an allowlisted check $\rightarrow$ abstains without claiming a verification result.

- **`FR-T2-02` (3-Tier Memory Model):**
  - Combines **Episodic Memory** (`:Finding` + `:Observation`), **Semantic Memory** (`:Service`, `:Code_Module`, `:Requirement`, `:CheckDefinition`), and **Procedural Memory** (`:Runbook` linked via `[:REMEDIATES]->(:Requirement)`) in a single FalkorDB graph.

- **`FR-T2-03` (Dynamic Evidence-Driven Tool Selection):**
  - Supported invalid payload evidence (`payload_valid == False`) dynamically selects the mapped schema verification branch (`CHK-WEBHOOK-ISO4217`) and skips unnecessary multi-hop patch traversal. An unmapped invalid-plan scenario is reported as `INSUFFICIENT_EVIDENCE` rather than being sent through an unrelated check.

- **`FR-T2-04` (Logical Multigraph Tenancy & Scope Validation):**
  - Switching tenants (`killbill-prod` $\leftrightarrow$ `nexus-commerce`) switches the underlying FalkorDB graph via `db.select_graph(f"falkortrace:{tenant_id}")` after allowlist validation via `validate_tenant_scope(tenant_id)`.

---

### 2.3 Company Brain & Decision Provenance (`FR-T3`)

- **`FR-T3-01` (Unified SDLC, Verification & Org Knowledge Graph):**
  - Connects client tickets, API payloads, microservices, Java/Go modules, versioned code artifacts, Git commits, PRD/SRD requirements, verification checks, execution observations, engineering squads, and on-call schedules in one graph.

- **`FR-T3-02` (4 Deterministic Answer Shapes & 3 Triage Verdicts):**
  - **Answer Shapes:** `answered_with_path` | `answered_from_memory` | `not_in_the_graph` | `unknown_service`
  - **Verdicts (when `answered_with_path`):**
    1. `PATCH_REGRESSION`: Sandboxed check reproduced a specification failure (`status == 'FAIL'`, `observed != expected`) on a candidate module modified in the blast radius.
    2. `WORKING_AS_PER_PRD`: Sandboxed check passed (`status == 'PASS'`, `observed == expected`); client expectation contradicts explicit PRD/SRD rule (e.g., `active_seats: 42 < 50`).
    3. `DATA_PAYLOAD_ISSUE`: Client webhook/API payload failed schema/constraint validation (`payload_valid: false`) while service code is healthy.

---

### 2.4 Seven Interactive Scenarios in the UI Bar (`killbill-prod`)

| Scenario Button | Target Service / Ticket | Verification & Memory Behavior | Expected Answer Shape & Verdict |
| :--- | :--- | :--- | :--- |
| **1. 4-Hop Patch Bug (4902)** | `billing-edge-api` (`TICKET-4902`) | Traverses 3 hops to `proration-engine`, runs `CHK-PRORATION-30-360` on `sha:9f82d1a` (`expected=$30.00`, `observed=$45.00`). | `answered_with_path` $\rightarrow$ `PATCH_REGRESSION` |
| **2. PRD Rule Match (4908)** | `invoice-orchestrator` (`TICKET-4908`) | Runs `CHK-DISCOUNT-SEAT-50` (`active_seats=42 < 50` $\rightarrow$ `0%` discount per `PRD-DISC-209`). | `answered_with_path` $\rightarrow$ `WORKING_AS_PER_PRD` |
| **3. Bad Webhook (4915)** | `payment-gateway-router` (`TICKET-4915`) | Dynamically runs `CHK-WEBHOOK-ISO4217` on `currency: "USDT-ERC20"` (`SRD-PAY-301`). | `answered_with_path` $\rightarrow$ `DATA_PAYLOAD_ISSUE` |
| **4. Isolated Island (4920)** | `audit-vault-archiver` (`TICKET-4920`) | `CALL algo.WCC` detects isolated Component #2 (`0` dependency paths). | `not_in_the_graph` $\rightarrow$ `UNMODELED_DEPENDENCY` |
| **5. Unknown Service Gate** | `quantum-ledger-v9` (No Ticket) | `resolve_service()` returns `None` at Gate (`0` downstream queries). | `unknown_service` $\rightarrow$ `UNMODELED_OR_UNKNOWN` |
| **6. Memory Hit (Exact Match)** | `billing-edge-api` (`TICKET-4902`) | Matches `(input_fingerprint, artifact_sha=9f82d1a)` $\rightarrow$ `REUSE_APPLICABLE_OBSERVATION`. | `answered_from_memory` $\rightarrow$ `PATCH_REGRESSION` |
| **7. Memory Guard: Diff Case (4905)** | `billing-edge-api` (`TICKET-4905`) | Same service as `4902`, different input (`cycle_day=29`) $\rightarrow$ `HYPOTHESIS_ONLY_DIFFERENT_INPUT`; runs check for Day 29 (`$6.00 vs $2.00`). | `answered_with_path` $\rightarrow$ `PATCH_REGRESSION` |
