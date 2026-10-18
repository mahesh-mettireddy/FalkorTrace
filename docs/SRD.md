# Software Requirements Document (SRD) — FalkorTrace

**Document ID:** `SRD-FALKORTRACE-2026-V2`  
**System Name:** FalkorTrace — Graph-Guided Software Investigation, Sandboxed Verification & Version-Aware Agent Memory  
**Target Platform:** FalkorDB (`falkordb/falkordb:v4.2.0` / FalkorDB Cloud) + FastAPI (Python 3.11+) + MCP Server + Zero-Build Interactive Web Dashboard  

---

## 1. System Purpose & Scope

**FalkorTrace** is a graph-guided software investigation and sandboxed verification platform built on **FalkorDB**. It connects software requirements (`PRD`/`SRD`), allowlisted verification checks (`CheckDefinition`), versioned code artifacts (`ArtifactVersion`), execution observations (`Observation`), client support tickets (`Client_Issue`), microservices (`Service`), source code modules (`Code_Module`), deployment patches (`Change`), engineering teams (`Team`), on-call rosters (`Person`), procedural runbooks (`Runbook`), and version-aware episodic memories (`Finding`) inside logical FalkorDB multigraphs.

### 1.1 System Design Goals
1. **Graph-Guided Sandboxed Verification:** Replaces reliance on pre-seeded boolean flags (`compliant: false`) with deterministic execution of allowlisted checks (`CHK-PRORATION-30-360`, `CHK-DISCOUNT-SEAT-50`, `CHK-WEBHOOK-ISO4217`, `CHK-TAX-ROUNDING`, `CHK-NEXUS-TTL`) against versioned code artifacts (`ArtifactVersion`) compared to independent requirement specifications.
2. **Version-Aware Investigation Memory:** Stamps every `(:Finding)` and `(:Observation)` with a Minimum Applicability Fingerprint `(tenant_id, service, input_fingerprint, artifact_sha, req_version, check_version)` and preserves historical findings as `STALE_VERSION_MISMATCH` when code artifacts change.
3. **Zero LLM-Generated Cypher & Read/Write Separation:** 100% of FalkorDB read queries are human-authored, parameterized openCypher patterns or native `CALL algo.<name>()` procedures executed via `graph.ro_query()`. State mutations (`record_finding`, `apply_hotfix_remediation`, `inject_live_fault`, `seed_tenant`) explicitly execute over `graph.query()`.
4. **Explicit Engine Mode Telemetry (`LIVE_FALKORDB` vs `IN_MEMORY_FALLBACK`):** Reports exact engine mode in `/api/health` and UI status badges, and supports `FALKORTRACE_STRICT_DB=1` to fail fast if live FalkorDB is unreachable.

---

## 2. System Components & Subsystem Specifications

### 2.1 Subsystem `SRD-DB-01`: Multi-Mode FalkorDB Connection & Multigraph Manager (`backend/db.py`)
- **Primary Engine:** Official `falkordb` Python client connecting via TCP/SSL to `FALKORDB_HOST:FALKORDB_PORT` (supports pinned `falkordb/falkordb:v4.2.0` container and managed FalkorDB Cloud instances).
- **Explicit Fallback & Strict Mode:** Exposes `engine_mode` (`LIVE_FALKORDB` or `IN_MEMORY_FALLBACK`) in `status()`. When `FALKORTRACE_STRICT_DB=1` is set, disables in-memory fallback so tests and CI can enforce live FalkorDB execution.
- **Logical Multigraph Namespace & Allowlist:** Every tenant request validates `tenant_id` via `validate_tenant_scope(tenant_id)` against `ALLOWED_TENANT_GRAPHS` (`killbill-prod`, `nexus-commerce`) before calling `db.select_graph(f"falkortrace:{tenant_id}")`.

### 2.2 Subsystem `SRD-VERIFIER-02`: Sandboxed Verification Runner & Applicability Fingerprinting (`backend/verifier.py`)
- **`ARTIFACT_VERSIONS_CATALOG`:** Stores distinct faulty and clean artifact revisions with SHA-256 code hashes (`9f82d1a` `v4.12.2-faulty` vs `7c31b09` `v4.12.1-clean` for `FixedAndRecurringInvoiceItemGenerator.java`, `88d12f0` vs `55a19c2` for `StockHoldCoordinator.go`, etc.).
- **`INDEPENDENT_REQUIREMENT_SPECIFICATIONS`:** Stores independent expected values for normal, boundary (`cycle_day=29`), and invalid-input cases without calling the code under test.
- **`execute_sandboxed_Verification_check()`:** Executes the allowlisted fixture against `artifact_sha` and returns a structured `Observation` dict (`observation_id`, `run_id`, `check_id`, `check_version`, `artifact_sha`, `code_hash`, `expected_value`, `observed_value`, `status`, `violation_reproduced`, `duration_ms`, `logs`).

### 2.3 Subsystem `SRD-SEED-03`: Idempotent Graph Seeder & Index Provisioner (`backend/seed.py`)
- Creates range indexes on lookup keys (`Service.name`, `Client_Issue.id`, `Requirement.id`, `Code_Module.name`, `Change.sha`, `CheckDefinition.id`).
- Seeds all services, weighted `:DEPENDS_ON` edges, code modules, `CheckDefinition` nodes, `ArtifactVersion` nodes, PRD/SRD requirements, runbooks, and 12 evaluation cases across `killbill-prod` and `nexus-commerce`.

### 2.4 Subsystem `SRD-TOOLS-04`: 12 Parameterized Cypher, GraphBLAS & Verification Tools (`backend/tools.py`)
- Implements 12 deterministic tools (`resolve_service`, `recall_past_findings`, `evaluate_memory_applicability`, `inspect_ticket_and_prd_lineage`, `trace_blast_radius`, `inspect_recent_patches`, `list_relevant_checks`, `run_approved_check`, `shortest_dependency_path`, `service_criticality_pagerank`, `analyze_topology_islands_and_bridges`, `record_finding`) plus simulated remediation and chaos fault actions.

### 2.5 Subsystem `SRD-AGENT-05`: Dynamic Graph-Guided Orchestrator & Entity-Reference Guardrail (`backend/agent.py`)
- Implements dynamic evidence-driven tool selection, version-aware memory gating, and the 12-case 4-System Benchmark (`run_head_to_head_benchmark`).
- Enforces `accepts(sentence, answer)` post-generation entity-reference verification (ensuring no ungrounded service or code module names appear in prose, while behavioral truth is established by the sandboxed `Observation`).

### 2.6 Subsystem `SRD-MCP-06`: Model Context Protocol (MCP) Server (`backend/mcp_server.py`)
- Exposes all 12 typed FalkorTrace tools over the Model Context Protocol (JSON-RPC 2.0 / stdio & FastAPI `/api/mcp/tools` and `/api/mcp/call` endpoints).

---

## 3. Non-Functional Requirements (NFRs)

| Requirement ID | Category | Specification |
| :--- | :--- | :--- |
| **NFR-PERF-01** | Graph Query & Verification Latency | Individual parameterized `ro_query` traversals, native algorithms (`SPpaths`, `pageRank`, `WCC`), and sandboxed check executions must complete in `< 25ms` on local/Cloud FalkorDB. |
| **NFR-SEC-01** | Cypher & Sandbox Safety | Zero string interpolation of user or LLM inputs into Cypher strings; `execute_sandboxed_Verification_check` only executes allowlisted `check_id` definitions with no shell or network access. |
| **NFR-ISO-01** | Logical Tenant Isolation | Tenant graphs (`falkortrace:killbill-prod` vs `falkortrace:nexus-commerce`) are isolated via `db.select_graph()` and gated by `validate_tenant_scope()`. |
| **NFR-MEM-01** | Zero Stale Memory Reuse | Changing an active `artifact_sha` via `/api/remediate` or `/api/inject-fault` must mark prior findings `STALE_VERSION_MISMATCH` (without deleting history) and prevent stale observation reuse (`0%` stale reuse error rate). |
| **NFR-HAL-01** | Entity-Reference Grounding | Any kebab-case service name or `.java`/`.kt`/`.go` module name in prose output not present in FalkorDB's returned `allowed_tokens` set must be rejected by `accepts()`. |
