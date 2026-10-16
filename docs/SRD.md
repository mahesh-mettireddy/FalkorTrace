# Software Requirements Document (SRD) — FalkorTrace

**Document ID:** `SRD-FALKORTRACE-2026-V1`  
**System Name:** FalkorTrace — Multi-Agent Graph Triage & Company Brain  
**Target Platform:** FalkorDB (Docker / FalkorDB Cloud) + FastAPI (Python 3.11+) + MCP Server + Zero-Build Interactive Web Dashboard  

---

## 1. System Purpose & Scope

**FalkorTrace** is an autonomous, graph-grounded multi-agent incident triage and company brain platform built on **FalkorDB**. It connects software requirements (`PRD`/`SRD`), client support tickets (`Client_Issue`), microservices (`Service`), source code modules (`Code_Module`), deployment patches (`Change`), engineering teams (`Team`), on-call rosters (`Person`), procedural runbooks (`Runbook`), and persistent episodic memories (`Finding`) inside hardware-isolated FalkorDB multigraphs.

### 1.1 System Design Goals
1. **Zero LLM-Generated Cypher:** 100% of FalkorDB queries are human-authored, parameterized openCypher patterns or native `CALL algo.<name>()` procedures exposed as typed tools.
2. **Read/Write Separation:** All analytical queries execute over `graph.ro_query()` (`GRAPH.RO_QUERY`). State mutations (`record_finding`, `apply_hotfix`, `seed_tenant`) explicitly execute over `graph.query()`.
3. **Sub-150ms Auto-Heal on Ephemeral Cloud Tiers:** Automatically detects if a FalkorDB Cloud Free Tier graph was evicted after inactivity (`MATCH (n:Service) RETURN count(n) LIMIT 1`) and transparently re-seeds the tenant graph in `<150ms`.
4. **100% Deterministic Operation (With Optional Guarded LLM Prose):** Operates with zero external API keys required, while supporting optional Gemini/OpenAI prose synthesis guarded by a post-generation regex token verifier (`accepts()`).

---

## 2. System Components & Subsystem Specifications

### 2.1 Subsystem `SRD-DB-01`: Multi-Mode FalkorDB Connection & Multigraph Manager (`backend/db.py`)
- **Primary Engine:** Official `falkordb` Python client connecting via TCP/SSL to `FALKORDB_HOST:FALKORDB_PORT` (supports local `falkordb/falkordb:latest` container and managed FalkorDB Cloud instances).
- **Resilient GraphBLAS-Compatible In-Memory Fallback:** If a local Docker daemon or Cloud endpoint is temporarily unreachable, seamlessly falls back to an embedded Cypher-compatible multigraph engine implementing `.select_graph()`, `.ro_query()`, `.query()`, and `.explain()` with identical result-set shapes so demos never fail.
- **Multigraph Namespace Convention:** Every tenant request resolves to `db.select_graph(f"falkortrace:{tenant_id}")`.
- **Supported Tenants Out-of-the-Box:**
  - `killbill-prod`: Enterprise SaaS Subscription & Invoicing Platform (8 microservices, 8 Java modules, 6 PRD/SRD specs, 6 patches, 4 teams, 6 engineers, 4 runbooks, 5 client tickets).
  - `nexus-commerce`: High-Frequency Global Checkout & Settlement Platform (6 microservices, 5 modules, 4 PRD/SRD specs, 4 patches, 3 teams, 4 engineers, 3 client tickets).

### 2.2 Subsystem `SRD-SEED-02`: Idempotent Graph Seeder & Index Provisioner (`backend/seed.py`)
- Creates range indexes on high-cardinality lookup keys:
  - `CREATE INDEX FOR (s:Service) ON (s.name)`
  - `CREATE INDEX FOR (i:Client_Issue) ON (i.id)`
  - `CREATE INDEX FOR (r:Requirement) ON (r.id)`
  - `CREATE INDEX FOR (c:Code_Module) ON (c.name)`
  - `CREATE INDEX FOR (ch:Change) ON (ch.sha)`
- Seeds all nodes and weighted relationships (`weightProp: 'weight'` on `:DEPENDS_ON` edges) in a single atomic batch.

### 2.3 Subsystem `SRD-TOOLS-03`: Parameterized Cypher & Native Algorithm Catalogue (`backend/tools.py`)
- Implements 8 deterministic tools plus a live graph remediation action.
- Wraps every call in a high-precision latency timer (`time.perf_counter()`) and captures FalkorDB's `GRAPH.EXPLAIN` execution plan for full observability.
- Includes FalkorDB's parallel-relationship uniqueness safeguard (`WHERE ID(e) >= 0`) on multi-hop edge matches.

### 2.4 Subsystem `SRD-AGENT-04`: Multi-Agent Triage Swarm & Hallucination Guardrail (`backend/agent.py`)
- Implements a 5-stage multi-agent coordination pipeline with explicit handoff records (`from_agent`, `to_agent`, `handoff_payload`, `duration_ms`).
- Enforces the 4 deterministic answer shapes (`answered_with_path`, `answered_from_memory`, `not_in_the_graph`, `unknown_service`).
- Enforces `accepts(sentence, answer)` post-generation token verification.

### 2.5 Subsystem `SRD-MCP-05`: Model Context Protocol (MCP) Server (`backend/mcp_server.py`)
- Exposes the fixed FalkorDB tool catalogue over the Model Context Protocol (JSON-RPC 2.0 / stdio & FastAPI `/api/mcp/tools` and `/api/mcp/call` endpoints) so external MCP clients (Claude Desktop, Cursor, Antigravity) can invoke FalkorTrace tools directly.

---

## 3. Non-Functional Requirements (NFRs)

| Requirement ID | Category | Specification |
| :--- | :--- | :--- |
| **NFR-PERF-01** | Graph Query Latency | Individual parameterized `ro_query` traversals and native algorithms (`SPpaths`, `pageRank`, `WCC`) must complete in `< 25ms` on local/Cloud FalkorDB. |
| **NFR-SEC-01** | Cypher Injection Immunity | Zero string interpolation of user or LLM inputs into Cypher strings. All inputs must pass `resolve_service()` and be bound via `$params` dictionaries. |
| **NFR-ISO-01** | Tenant Isolation | Tenant graphs (`falkortrace:killbill-prod` vs `falkortrace:nexus-commerce`) must be isolated at the `db.select_graph()` layer with zero shared nodes. |
| **NFR-REL-01** | Cloud Free-Tier Resilience | Handles FalkorDB Cloud Free Tier constraints (100MB RAM limit, 24h idle sleep, no disk persistence) via automatic `ensure_tenant_seeded()` guard (`< 150ms`). |
| **NFR-HAL-01** | Zero Entity Hallucination | Any kebab-case service name or `.java` module name in prose output not present in FalkorDB's returned `allowed_tokens` set must be rejected by `accepts()`. |
