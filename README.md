# FalkorTrace

**Multi-Agent Graph Triage Swarm & Enterprise Company Brain on FalkorDB**

[![Database](https://img.shields.io/badge/FalkorDB-v4.22_GraphBLAS-indigo)](https://www.falkordb.com/)
[![Backend](https://img.shields.io/badge/FastAPI-Python_3.11-009688)](https://fastapi.tiangolo.com/)
[![Protocol](https://img.shields.io/badge/MCP-Model_Context_Protocol-amber)](https://modelcontextprotocol.io/)
[![Tests](https://img.shields.io/badge/Pytest-8%2F8_Passing-emerald)](./tests/test_falkortrace.py)

---

## Overview

When an enterprise SaaS customer reports a production billing or subscription anomaly (modeled on **Kill Bill**, the open-source enterprise Java subscription and invoicing platform), on-call engineers spend hours correlating support tickets, PRD/SRD business specifications, microservice dependency chains, recent Git commits, and PagerDuty rosters.

**FalkorTrace** unifies the entire operational and SDLC topology inside **FalkorDB**. Instead of vector RAG—which chunks documents and forces an LLM to guess structural relationships—FalkorTrace orchestrates a **5-Agent Triage Swarm** executing **deterministic, parameterized Cypher queries (`graph.ro_query`)** and **native FalkorDB GraphBLAS algorithms (`algo.SPpaths`, `algo.pageRank`, `algo.WCC`, `algo.betweenness`)** exposed over the **Model Context Protocol (MCP)**.

Every investigation deterministically classifies the incident into one of **4 Answer Shapes** (`answered_with_path`, `answered_from_memory`, `not_in_the_graph`, `unknown_service`) and adjudicates the root cause:

| Verdict | Meaning | Provenance Path Verified in FalkorDB |
| :--- | :--- | :--- |
| **`PATCH_REGRESSION`** | A recent deployment modified a downstream code module (up to 4 hops away) and violated a linked PRD/SRD clause. | `(:Client_Issue)-[:REPORTS_ON]->(:Service)-[:DEPENDS_ON*1..4]->(:Service)-[:IMPLEMENTED_BY]->(:Code_Module)<-[:MODIFIED]-(:Change)` |
| **`WORKING_AS_PER_PRD`** | All traversed code modules and patches are compliant; the client's expectation contradicts an explicit PRD/SRD contract rule. | `(:Service)-[:IMPLEMENTED_BY]->(:Code_Module)-[:IMPLEMENTS {compliant: true}]->(:Requirement)` |
| **`DATA_PAYLOAD_ISSUE`** | The client sent a malformed webhook/API payload (e.g., non-ISO currency `"USDT-ERC20"` or `null` idempotency key) rejected per SRD spec. | `(:Client_Issue {payload_valid: false})-[:REPORTS_ON]->(:Service)-[:IMPLEMENTED_BY]->(:Code_Module)-[:IMPLEMENTS]->(:Requirement)` |
| **`UNMODELED_DEPENDENCY` / `UNMODELED_OR_UNKNOWN`** | The queried service either sits in an isolated WCC island (`not_in_the_graph`) or does not exist in the tenant graph (`unknown_service`). | Blocked at `resolve_service` Entity Resolution Gate or detected via `CALL algo.WCC(...)`. |

---

## System Architecture

```text
+---------------------------------------------------------------------------------------------------+
|                        FALKORTRACE 3-PANE DARK-MODE OPERATIONS DASHBOARD                          |
|  [Left: Scenario Presets + Depth 1..4 Slider]  [Center: 2D Bezier DAG]  [Right: Trace, PRD & MCP] |
+-------------------------------------------------+-------------------------------------------------+
                                                  | REST JSON (/api/triage, /api/ask, /api/graph)
                                                  v
+---------------------------------------------------------------------------------------------------+
|                             FASTAPI BACKEND & MCP SERVER (backend/)                               |
|                                                                                                   |
|  [Agent 1: Entity Gate] ---> [Agent 2: Episodic Memory] ---> [Agent 3: PRD & Payload Auditor]     |
|   resolve_service()           recall_past_findings()          inspect_ticket_and_prd_lineage()    |
|          |                            |                                      |                    |
|          | (0 rows -> HALT:           | (Hit -> answered_from_memory         v                    |
|          |  unknown_service)          |  in 1 hop!)            [Agent 4: Topology & Patch Swarm]  |
|                                       |                        trace_blast_radius(*1..4)          |
|                                       |                        inspect_recent_patches()           |
|                                       |                        shortest_dependency_path(SPpaths)  |
|                                       |                                      |                    |
|                                       v                                      v                    |
|                        [Post-Gen Hallucination Guardrail] <--- [Agent 5: Criticality & Oncall]    |
|                         accepts(sentence, allowed_tokens)      service_criticality_pagerank()     |
|                                                                analyze_topology_islands(WCC)      |
|                                                                record_finding() [Episodic Write]  |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                db.select_graph("falkortrace:killbill-prod") | db.select_graph("falkortrace:nexus-commerce")
                graph.ro_query(cypher, params) [Reads]       | graph.query(cypher, params) [Memory Writes]
                                                  v
+---------------------------------------------------------------------------------------------------+
|                       FALKORDB MULTIGRAPH ENGINE (GraphBLAS Sparse Matrices)                      |
|   (:Client_Issue)-[:REPORTS_ON]->(:Service)-[:DEPENDS_ON*1..4]->(:Service)-[:IMPLEMENTED_BY]->    |
|   (:Code_Module)-[:IMPLEMENTS {compliant}]->(:Requirement)<-[:REMEDIATES]-(:Runbook)              |
|   (:Change)-[:MODIFIED]->(:Code_Module) | (:Person)-[:ONCALL_FOR]->(:Team)-[:OWNS]->(:Service)    |
+---------------------------------------------------------------------------------------------------+
```

---

## Core Engineering Guarantees

1. **Zero LLM-Generated Cypher:** All graph reads execute through 8 fixed, human-authored parameterized Cypher tools in [`backend/tools.py`](./backend/tools.py).
2. **Strict Read/Write Separation (`ro_query`):** Every inspection tool executes via `graph.ro_query(cypher, params)`. Only episodic memory persistence (`record_finding`) and live hotfix rollbacks (`apply_hotfix_remediation`) use `graph.query()`.
3. **Entity Resolution Gate:** [`resolve_service`](./backend/tools.py) verifies that a microservice exists in FalkorDB before any multi-hop traversal runs. Unknown entities halt immediately with `0` downstream queries.
4. **Native FalkorDB Graph Algorithms:**
   - `CALL algo.SPpaths(...)` — Computes weighted shortest dependency paths from entrypoint service to root-cause service.
   - `CALL algo.pageRank('Service', 'DEPENDS_ON')` — Ranks structural blast-radius criticality across the microservice estate.
   - `CALL algo.WCC(...)` & `CALL algo.betweenness(...)` — Detects isolated architectural islands (`not_in_the_graph`) and bottleneck bridge services.
5. **Hardware-Isolated Multi-Tenant Graphs:** Isolates tenant state via `db.select_graph(f"falkortrace:{tenant_id}")` (`falkortrace:killbill-prod` and `falkortrace:nexus-commerce`).
6. **Post-Generation Hallucination Guardrail (`accepts()`):** [`accepts(sentence, answer)`](./backend/agent.py) extracts every kebab-case service token and `.java`/`.kt`/`.go` filename from generated prose and rejects any output referencing entities absent from the FalkorDB result set.

---

## Graph Data Model (Cypher Schema)

### Nodes
- `(:Client_Issue {id, title, client_name, client_tier, reported_service, reported_payload, payload_valid, payload_error, expected_behavior, actual_behavior, created_at})`
- `(:Service {name, tier, language, repo, description})`
- `(:Code_Module {name, filepath, method_name, governed_field, logic_summary})`
- `(:Requirement {id, doc_type, title, rule_text, version})` *(`PRD` or `SRD`)*
- `(:Change {sha, patch_version, summary, regressions_introduced, diff_snippet, at, hours_ago, author})`
- `(:Team {name, slack_channel, pagerduty_schedule})`
- `(:Person {name, handle, email, role})`
- `(:Runbook {id, verdict_type, title, steps})` *(Procedural Memory)*
- `(:Finding {id, verdict, text, root_cause_node, ticket_id, at, session})` *(Episodic Memory)*

### Relationships
```cypher
(issue:Client_Issue)-[:REPORTS_ON]->(s:Service)
(upstream:Service)-[:DEPENDS_ON {kind, weight, critical}]->(downstream:Service)
(s:Service)-[:IMPLEMENTED_BY]->(c:Code_Module)
(c:Code_Module)-[:IMPLEMENTS {compliant, note}]->(r:Requirement)
(ch:Change)-[:MODIFIED]->(c:Code_Module)
(ch:Change)-[:DEPLOYED_TO]->(s:Service)
(t:Team)-[:OWNS]->(s:Service)
(p:Person)-[:MEMBER_OF]->(t:Team)
(p:Person)-[:ONCALL_FOR {from, to}]->(t:Team)
(p:Person)-[:WORKED_ON {commits}]->(s:Service)
(f:Finding)-[:ABOUT]->(s:Service)
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
│   ├── db.py                        # FalkorDB Cloud/Docker Manager + Auto-Seed Guard
│   ├── seed.py                      # Idempotent Multi-Tenant Graph Seeder
│   ├── tools.py                     # 8 Parameterized Cypher & GraphBLAS Algorithm Tools
│   ├── agent.py                     # 5-Agent Triage Swarm + accepts() Guardrail
│   ├── mcp_server.py                # Model Context Protocol (MCP) Tool Server
│   └── main.py                      # FastAPI REST & MCP Application
├── frontend/
│   └── index.html                   # 3-Pane Interactive SVG DAG Operations Dashboard
├── docs/
│   ├── ARCHITECTURE_AND_DESIGN.md   # System Architecture & Data Model Specification
│   ├── SRD.md                       # Software Requirements Document
│   └── FRD.md                       # Functional Requirements Document
├── tests/
│   └── test_falkortrace.py          # End-to-End Pytest Verification Suite (8 Tests)
├── Dockerfile
├── docker-compose.yml
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

### 2. Docker Compose (Local FalkorDB Container + FalkorTrace App)
```bash
docker compose up --build
```

### 3. Run End-to-End Verification Suite
```bash
pytest -v
```

---

## REST & MCP API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | FalkorDB connection status, active multigraphs, and MCP tool count |
| `GET` | `/api/graph?tenant_id=killbill-prod` | Full node and directed edge topology for the active tenant graph |
| `POST` | `/api/triage` | Execute the 5-Agent Triage Swarm for a `(service, ticket_id, depth)` |
| `POST` | `/api/ask` | Natural-language question router (`"Why was ACME overcharged on TICKET-4902?"`) |
| `POST` | `/api/compare-depth` | Side-by-side comparison of shallow `depth=1` vs. multi-hop `depth=4` |
| `POST` | `/api/remediate` | Live graph hotfix rollback restoring PRD compliance in FalkorDB |
| `POST` | `/api/memory/clear` | Clear `(:Finding)` episodic memory nodes for the active tenant |
| `POST` | `/api/seed` | Reset and re-seed the specified tenant graph |
| `GET` | `/api/mcp/tools` | Model Context Protocol (MCP) tool definitions and JSON schemas |
| `POST` | `/api/mcp/call` | Execute any parameterized MCP tool directly |
