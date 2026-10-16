# Functional Requirements Document (FRD) — FalkorTrace

**Document ID:** `FRD-FALKORTRACE-2026-V1`  
**Project:** FalkorTrace — Multi-Agent Graph Triage & Company Brain  

---

## 1. Functional Overview & Track Mapping

FalkorTrace fulfills functional requirements across all three hackathon tracks simultaneously:
- **Track 01 (Agents That Act on Connected Data):** `FR-T1-01` through `FR-T1-05`
- **Track 02 (Agent Memory & Coordination):** `FR-T2-01` through `FR-T2-04`
- **Track 03 (Company Brain):** `FR-T3-01` through `FR-T3-04`
- **3-Pane Operations UI & Interactive Scenarios:** `FR-UI-01` through `FR-UI-06`

---

## 2. Detailed Functional Requirements

### 2.1 Entity Resolution & Guarded Tool Execution (`FR-T1`)

- **`FR-T1-01` (Entity Resolution Gate):**
  - *Input:* `service: str`
  - *Behavior:* Executes `MATCH (s:Service {name: $name}) RETURN s.name AS name, s.tier AS tier, s.description AS description` via `graph.ro_query()`.
  - *Output:* If empty, immediately halts the agent loop and returns `outcome = "unknown_service"` with `0` downstream queries.

- **`FR-T1-02` (Depth-Controlled Blast Radius Traversal):**
  - *Input:* `service: str`, `depth: int (1..4)`
  - *Behavior:* Traverses `(s:Service {name: $service})-[e:DEPENDS_ON*1..4]->(dep:Service)` with `WHERE length(path) <= $depth` and returns `dep.name`, `dep.tier`, `length(path) AS hops`, and `[n IN nodes(path) | n.name] AS via`.
  - *Demo Proof:* On `TICKET-4902` (`billing-edge-api`), `depth=1` returns only `subscription-service` (clean), whereas `depth=4` uncovers `proration-engine` at Hop 3 where the broken patch resides.

- **`FR-T1-03` (Multi-Hop Patch & PRD Compliance Audit):**
  - *Input:* `service: str`, `depth: int (1..4)`, `hours: int (default 72)`
  - *Behavior:* Traverses up to `$depth` hops downstream from `$service`, matching `(dep:Service)-[:IMPLEMENTED_BY]->(c:Code_Module)<-[:MODIFIED]-(ch:Change)` and `(c)-[impl:IMPLEMENTS]->(r:Requirement)` where `ch.hours_ago <= $hours`.
  - *Output:* Returns modified Java classes, commit SHAs, patch versions, authors, diff snippets, and `impl.compliant` boolean flags alongside the violated `PRD`/`SRD` rule text.

- **`FR-T1-04` (Native FalkorDB Graph Algorithms as Tools):**
  - **Shortest Dependency Path (`shortest_dependency_path`):** Executes `CALL algo.SPpaths({sourceNode: a, targetNode: b, relTypes: ['DEPENDS_ON'], relDirection: 'outgoing', weightProp: 'weight', pathCount: 1}) YIELD path, pathWeight`.
  - **Service Criticality & Oncall Escalation (`service_criticality_pagerank`):** Executes `CALL algo.pageRank('Service', 'DEPENDS_ON') YIELD node, score` and joins `(p:Person)-[:ONCALL_FOR]->(t:Team)-[:OWNS]->(s:Service)` plus `(expert:Person)-[w:WORKED_ON]->(s:Service)` to identify both the primary on-call responder and the top code contributor.
  - **Topology Island & Chokepoint Detection (`analyze_topology_islands_and_bridges`):** Executes `CALL algo.WCC` and `CALL algo.betweenness` to identify isolated services (powering `not_in_the_graph`) and bridge bottlenecks.

- **`FR-T1-05` (Live Graph Remediation / Action on Connected Data):**
  - *Input:* `tenant_id: str`, `service: str`, `patch_sha: str`
  - *Behavior:* Allows the operator to trigger **"Apply Hotfix / Rollback Patch"** directly from the UI. Mutates FalkorDB (`SET impl.compliant = true`, `SET ch.regressions_introduced = false`, creates a hotfix `:Change` node, and clears stale `:Finding` nodes) so re-running triage immediately reflects the healed Company Brain state.

---

### 2.2 Multi-Agent Memory & Coordination (`FR-T2`)

- **`FR-T2-01` (Cross-Session Episodic Memory Write & Recall):**
  - Every resolved investigation writes a `(:Finding {id, verdict, text, root_cause_node, ticket_id, at, session})` node linked via `[:ABOUT]` to the entry `:Service`.
  - Before any multi-hop traversal, **Agent 1 (Episodic Memory Auditor)** calls `recall_past_findings(service)`. If a finding exists and `bypass_memory=False`, FalkorTrace returns `outcome = "answered_from_memory"` in `~1ms`.

- **`FR-T2-02` (3-Tier Memory Model):**
  - Combines **Episodic Memory** (`:Finding`), **Semantic Memory** (`:Service`, `:Code_Module`, `:Requirement`), and **Procedural Memory** (`:Runbook` linked via `[:REMEDIATES]->(:Requirement)`) in a single FalkorDB graph.

- **`FR-T2-03` (Structured Multi-Agent Handoffs):**
  - Records explicit handoff telemetry across 5 specialized agents:
    1. `Entity-Resolution-Gate`
    2. `Episodic-Memory-Auditor`
    3. `PRD-and-Payload-Auditor`
    4. `Topology-and-Patch-Inspector`
    5. `Centrality-and-Escalation-Coordinator`

- **`FR-T2-04` (Hardware-Isolated Multigraph Tenancy):**
  - Switching tenants in the UI (`killbill-prod` <-> `nexus-commerce`) switches the underlying FalkorDB graph via `db.select_graph(f"falkortrace:{tenant_id}")`.

---

### 2.3 Company Brain & Decision Provenance (`FR-T3`)

- **`FR-T3-01` (Unified SDLC & Org Knowledge Graph):**
  - Connects client tickets, API payloads, microservices, Java classes, Git commits, PRD/SRD requirements, engineering squads, on-call schedules, and commit history in one graph.

- **`FR-T3-02` (4 Deterministic Answer Shapes & 3 Triage Verdicts):**
  - **Answer Shapes:** `answered_with_path` | `answered_from_memory` | `not_in_the_graph` | `unknown_service`
  - **Verdicts (when `answered_with_path`):**
    1. `PATCH_REGRESSION`: Recent patch broke PRD/SRD compliance at Hop $k \in [0..4]$.
    2. `WORKING_AS_PER_PRD`: Code is 100% compliant and recent patches are clean; client expectation contradicts explicit PRD/SRD rule (e.g., `active_seats: 42 < 50`).
    3. `DATA_PAYLOAD_ISSUE`: Client webhook/API payload failed schema/ISO validation (`payload_valid: false`) against an SRD contract while code is healthy.

---

### 2.4 Five Interactive Pre-Wired Scenarios (`killbill-prod`)

| Scenario Button | Target Service / Ticket | Depth Behavior | Expected Answer Shape & Verdict |
| :--- | :--- | :--- | :--- |
| **Scenario 1: 4-Hop Patch Regression** | `billing-edge-api` (`TICKET-4902`) | At `depth=1`: Misses bug! At `depth=4`: Catches `sha:9f82d1a` on `proration-engine` (Hop 3) violating `PRD-INV-104`. | `answered_with_path` -> `PATCH_REGRESSION` (Subsequent run returns `answered_from_memory`!) |
| **Scenario 2: Working as per PRD** | `invoice-orchestrator` (`TICKET-4908`) | Traverses `DiscountPolicyEvaluator.java` -> `PRD-DISC-209` (requires $\ge 50$ seats; client has `42`). | `answered_with_path` -> `WORKING_AS_PER_PRD` |
| **Scenario 3: Bad Client Payload** | `payment-gateway-router` (`TICKET-4915`) | Validates payload (`currency: "USDT-ERC20"`, `idempotency_key: null`) against `SRD-PAY-301`. | `answered_with_path` -> `DATA_PAYLOAD_ISSUE` |
| **Scenario 4A: Unknown Service Check** | `legacy-cobol-mainframe` (No Ticket) | `resolve_service()` returns `None` at Gate. `0` downstream queries run. | `unknown_service` -> `UNMODELED_OR_UNKNOWN` |
| **Scenario 4B: Disconnected Island Check** | `audit-vault-archiver` (`TICKET-4920`) | Service exists in FalkorDB (WCC Island #2), but has `0` dependency paths to billing pipeline. | `not_in_the_graph` -> `UNMODELED_DEPENDENCY` |
