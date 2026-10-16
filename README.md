---
title: FalkorTrace — Multi-Agent Graph Triage & Company Brain
emoji: ⚡
colorFrom: indigo
colorTo: rose
sdk: gradio
app_file: app.py
app_port: 7860
pinned: true
short_description: Multi-Agent Graph Triage Swarm & Company Brain on FalkorDB
---

# FalkorTrace — Multi-Agent Graph Triage & Company Brain on FalkorDB

> **WeMakeDevs x FalkorDB Hackathon ("Graph Hacks: Context for AI Agents" — Oct 15–18, 2026)**  
> **Team Name:** LeoForge (`YVSBFW`) • **Team Leader:** Mahesh Babu Metti Reddy (`@maheshmettireddy`)  
> **Tracks Entered:**  
> - 🧠 **Track 03: Company Brain** *(Primary Target)*  
> - 🕵️ **Track 01: Agents That Act on Connected Data** *(Co-Primary)*  
> - 🤖 **Track 02: Agent Memory and Coordination** *(Co-Primary)*  
> - ✍️ **Side Prize: Best Blog Post** *(See [`docs/BLOG_POST_SUBMISSION.md`](docs/BLOG_POST_SUBMISSION.md))*

---

## 1. What Is FalkorTrace?

When an enterprise SaaS customer reports a production billing or subscription anomaly (modeled on **Kill Bill**, the open-source enterprise Java subscription & invoicing engine), on-call engineers lose hours stitching together Jira tickets, PRD/SRD specs, microservice dependency graphs, recent Git commits, and PagerDuty rosters.

**FalkorTrace** puts the entire operational and SDLC context inside **FalkorDB**. Instead of vector RAG—which chunks documents and forces an LLM to guess relationships—FalkorTrace uses a **5-Agent Triage Swarm** armed with **fixed, human-authored parameterized Cypher queries** and **native FalkorDB GraphBLAS algorithms (`algo.SPpaths`, `algo.pageRank`, `algo.WCC`, `algo.betweenness`)** exposed over the **Model Context Protocol (MCP)**.

Every investigation deterministically classifies the incident into one of **4 Answer Shapes** (`answered_with_path`, `answered_from_memory`, `not_in_the_graph`, `unknown_service`) and adjudicates whether the root cause is:
1. **`PATCH_REGRESSION`**: A recent commit modified a downstream Java module (up to 4 hops away) and violated a linked `PRD`/`SRD` clause.
2. **`WORKING_AS_PER_PRD`**: All traversed code modules and patches are compliant; the client's expectation contradicts an explicit `PRD`/`SRD` business rule (e.g., `active_seats: 42 < 50`).
3. **`DATA_PAYLOAD_ISSUE`**: The client sent a malformed webhook/API payload (e.g., `"currency": "USDT-ERC20"`, `"idempotency_key": null`) that was rightly rejected per `SRD-PAY-301`.
4. **`UNMODELED_OR_UNKNOWN` / `UNMODELED_DEPENDENCY`**: The service is either absent from the graph (`unknown_service` caught at the `resolve_service` gate) or sits in an isolated WCC island (`not_in_the_graph`).

---

## 2. System Architecture

```text
+---------------------------------------------------------------------------------------------------+
|                        FALKORTRACE 3-PANE DARK-MODE OPERATIONS DASHBOARD                          |
|  [Left: 4 Preset Scenarios + Depth 1..4 Slider]  [Center: 2D SVG Graph]  [Right: MCP Trace & PRD] |
+-------------------------------------------------+-------------------------------------------------+
                                                  | REST JSON (/api/triage, /api/graph, /api/remediate)
                                                  v
+---------------------------------------------------------------------------------------------------+
|                             FASTAPI BACKEND & MCP SERVER (backend/)                               |
|                                                                                                   |
|  [Agent 1: Entity Gate] ---> [Agent 2: Episodic Memory] ---> [Agent 3: PRD & Payload Auditor]     |
|   resolve_service()           recall_past_findings()          inspect_ticket_and_prd_lineage()    |
|          |                            |                                      |                    |
|          | (0 rows -> HALT:           | (Hit -> answered_from_memory         v                    |
|          |  unknown_service)          |  in ~1ms!)            [Agent 4: Topology & Patch Swarm]   |
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

## 3. Graph Data Model (Cypher Schema)

### Node Labels
- `(:Client_Issue {id, title, client_name, client_tier, reported_service, reported_payload, payload_valid, payload_error, expected_behavior, actual_behavior, created_at})`
- `(:Service {name, tier, language, repo, description})`
- `(:Code_Module {name, filepath, method_name, logic_summary})`
- `(:Requirement {id, doc_type, title, rule_text, version})` *(where `doc_type` is `'PRD'` or `'SRD'`)*
- `(:Change {sha, patch_version, summary, regressions_introduced, diff_snippet, at, hours_ago, author})`
- `(:Team {name, slack_channel, pagerduty_schedule})`
- `(:Person {name, handle, email, role})`
- `(:Runbook {id, verdict_type, title, steps})` *(Procedural Agent Memory)*
- `(:Finding {id, verdict, text, root_cause_node, ticket_id, at, session})` *(Episodic Agent Memory)*

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

## 4. The Fixed Parameterized Cypher & Native Algorithm Tools (`backend/tools.py`)

FalkorTrace **never** lets an LLM write raw Cypher. Every read tool executes strictly via `graph.ro_query(cypher, params)`:

### 1. `resolve_service` (Entity Resolution Gate)
```cypher
MATCH (s:Service {name: $name})
RETURN s.name AS name, s.tier AS tier, s.language AS language, s.repo AS repo, s.description AS description
```

### 2. `recall_past_findings` (Cross-Session Episodic Memory Read)
```cypher
MATCH (f:Finding)-[e:ABOUT]->(s:Service {name: $service})
WHERE ID(e) >= 0
RETURN f.id AS id, f.verdict AS verdict, f.text AS text,
       f.root_cause_node AS root_cause_node, f.ticket_id AS ticket_id,
       f.at AS at, f.session AS session
ORDER BY f.at DESC
LIMIT $limit
```

### 3. `inspect_ticket_and_prd_lineage` (Requirements & Payload Auditor)
```cypher
MATCH (i:Client_Issue {id: $ticket_id})-[:REPORTS_ON]->(s:Service)
OPTIONAL MATCH (s)-[:IMPLEMENTED_BY]->(c:Code_Module)-[impl:IMPLEMENTS]->(r:Requirement)
OPTIONAL MATCH (rb:Runbook)-[:REMEDIATES]->(r)
RETURN i.id AS ticket_id, i.title AS title, i.client_name AS client_name,
       i.client_tier AS client_tier, s.name AS reported_service,
       i.reported_payload AS reported_payload, i.payload_valid AS payload_valid,
       i.payload_error AS payload_error, i.expected_behavior AS expected_behavior,
       i.actual_behavior AS actual_behavior, c.name AS code_module,
       c.filepath AS filepath, c.method_name AS method_name,
       c.logic_summary AS logic_summary, impl.compliant AS compliant,
       impl.note AS compliance_note, r.id AS req_id, r.doc_type AS doc_type,
       r.title AS req_title, r.rule_text AS rule_text,
       rb.id AS runbook_id, rb.title AS runbook_title, rb.steps AS runbook_steps
```

### 4. `trace_blast_radius` (Variable-Length Multi-Hop Traversal)
```cypher
MATCH path = (s:Service {name: $service})-[:DEPENDS_ON*1..4]->(dep:Service)
WHERE length(path) <= $depth
RETURN DISTINCT dep.name AS dependency, dep.tier AS tier,
       length(path) AS hops, [n IN nodes(path) | n.name] AS via
ORDER BY hops ASC, dependency ASC
```

### 5. `inspect_recent_patches` (Multi-Hop Code & Patch Inspector)
```cypher
MATCH path = (s:Service {name: $service})-[:DEPENDS_ON*0..4]->(dep:Service)
WHERE length(path) <= $depth
MATCH (dep)-[:IMPLEMENTED_BY]->(c:Code_Module)<-[:MODIFIED]-(ch:Change)
WHERE ch.hours_ago <= $hours
OPTIONAL MATCH (c)-[impl:IMPLEMENTS]->(r:Requirement)
OPTIONAL MATCH (rb:Runbook)-[:REMEDIATES]->(r)
RETURN dep.name AS service, length(path) AS hops, [n IN nodes(path) | n.name] AS via,
       c.name AS code_module, c.filepath AS filepath, c.method_name AS method_name,
       ch.sha AS sha, ch.patch_version AS patch_version, ch.summary AS summary,
       ch.author AS author, ch.at AS at, ch.hours_ago AS hours_ago,
       ch.regressions_introduced AS regressions_introduced, ch.diff_snippet AS diff_snippet,
       impl.compliant AS compliant, impl.note AS compliance_note,
       r.id AS req_id, r.doc_type AS doc_type, r.title AS req_title, r.rule_text AS rule_text,
       rb.id AS runbook_id, rb.steps AS runbook_steps
ORDER BY impl.compliant ASC, ch.hours_ago ASC, hops ASC
```

### 6. `shortest_dependency_path` (FalkorDB Native `algo.SPpaths`)
```cypher
MATCH (a:Service {name: $source}), (b:Service {name: $target})
CALL algo.SPpaths({
    sourceNode: a,
    targetNode: b,
    relTypes: ['DEPENDS_ON'],
    relDirection: 'outgoing',
    weightProp: 'weight',
    pathCount: 1
})
YIELD path, pathWeight
RETURN [n IN nodes(path) | n.name] AS hops, pathWeight AS weight
```

### 7. `service_criticality_pagerank` (FalkorDB Native `algo.pageRank` + Oncall Resolver)
```cypher
CALL algo.pageRank('Service', 'DEPENDS_ON')
YIELD node, score
RETURN node.name AS service, node.tier AS tier, score
ORDER BY score DESC;

MATCH (p:Person)-[oc:ONCALL_FOR]->(t:Team)-[ow:OWNS]->(s:Service {name: $service})
WHERE ID(oc) >= 0 AND ID(ow) >= 0
OPTIONAL MATCH (expert:Person)-[w:WORKED_ON]->(s)
RETURN t.name AS team, t.slack_channel AS slack_channel, t.pagerduty_schedule AS pagerduty_schedule,
       p.name AS oncall_name, p.handle AS oncall_handle, p.email AS oncall_email, p.role AS oncall_role,
       expert.handle AS expert_handle, expert.name AS expert_name, w.commits AS expert_commits
ORDER BY w.commits DESC
LIMIT 1
```

### 8. `analyze_topology_islands_and_bridges` (FalkorDB Native `algo.WCC` & `algo.betweenness`)
```cypher
CALL algo.WCC({nodeLabels: ['Service'], relationshipTypes: ['DEPENDS_ON']})
YIELD node, componentId
RETURN node.name AS service, componentId
ORDER BY componentId ASC, service ASC;

CALL algo.betweenness({nodeLabels: ['Service'], relationshipTypes: ['DEPENDS_ON'], samplingSeed: 42})
YIELD node, score
RETURN node.name AS service, score
ORDER BY score DESC
```

### 9. `record_finding` (Episodic Memory Write via `graph.query()`)
```cypher
MATCH (s:Service {name: $service})
CREATE (f:Finding {
    id: $id,
    verdict: $verdict,
    text: $text,
    root_cause_node: $root_cause_node,
    ticket_id: $ticket_id,
    at: $at,
    session: $session
})
CREATE (f)-[:ABOUT]->(s)
RETURN f.id AS id, f.at AS at
```

---

## 5. Quickstart & Setup Instructions

### Option A: 1-Command Docker Compose (FalkorDB + FalkorTrace App)
```bash
docker compose up --build
```
- **FalkorTrace Operations Dashboard:** http://localhost:8000
- **FalkorDB Browser UI:** http://localhost:3000
- **FalkorDB TCP Port:** `localhost:6379`

### Option B: Local Python + FalkorDB Docker or FalkorDB Cloud
```bash
# 1. Start FalkorDB container (optional — if omitted, FalkorTrace uses its built-in GraphBLAS fallback engine)
docker run --rm -d -p 6379:6379 -p 3000:3000 falkordb/falkordb:latest

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Seed both tenant graphs ('falkortrace:killbill-prod' & 'falkortrace:nexus-commerce')
python -m backend.seed

# 4. Start FastAPI server
uvicorn backend.main:app --reload --port 8000
```
Open **http://localhost:8000** in your browser.

### Option C: Connecting to FalkorDB Cloud (`app.falkordb.cloud`)
Set the following in `.env` (or click the **FalkorDB Connection** button in the top navbar of the UI at runtime):
```env
FALKORDB_HOST=your-instance.falkordb.cloud
FALKORDB_PORT=6379
FALKORDB_USERNAME=default
FALKORDB_PASSWORD=your_cloud_password
FALKORDB_SSL=true
```
FalkorTrace includes an automatic **`ensure_tenant_seeded()` guard** that checks `MATCH (n:Service) RETURN count(n) LIMIT 1` before every request and re-seeds the graph in `<150ms` if the Free Tier instance woke from inactivity.

---

## 6. Running the Automated Verification Suite
```bash
pytest -v
```

---

## 7. AI Coding Assistant Disclosure (Rule #11 Compliance)
In accordance with Rule #11 of the WeMakeDevs x FalkorDB Graph Hacks rules: **Google Antigravity** was used as an AI pair-programming assistant during the hackathon to accelerate boilerplate generation, SVG dashboard layout, and documentation formatting. All graph data modeling, Cypher query parameterization, native algorithm selection (`SPpaths`, `pageRank`, `WCC`, `betweenness`), and the `accepts()` hallucination guardrail architecture were designed, verified, and tested by Team LeoForge.
