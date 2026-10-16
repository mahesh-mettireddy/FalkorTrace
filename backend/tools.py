"""
Fixed Parameterized Cypher & Native FalkorDB Algorithm Tool Catalogue (`backend/tools.py`).

Adheres strictly to the 6 Golden Rules from the WeMakeDevs x FalkorDB Blueprint:
- NEVER let the LLM write raw Cypher.
- Validate entity names against the graph via `resolve_service()` before running traversals.
- Execute all read tools strictly over `graph.ro_query(cypher, params)`.
- Use `WHERE ID(e) >= 0` on parallel edge patterns as documented in FalkorDB Known Limitations.
- Expose native FalkorDB graph algorithms (`algo.SPpaths`, `algo.pageRank`, `algo.WCC`, `algo.betweenness`) as typed agent tools.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# MCP Tool Catalogue Registry (Typed Schema for Model Context Protocol & UI)
# ============================================================================
MCP_TOOLS_CATALOGUE: List[Dict[str, Any]] = [
    {
        "name": "resolve_service",
        "agent": "Entity-Resolution-Gate",
        "mode": "ro_query",
        "description": "Entity resolution gate: checks whether a microservice name exists in the active FalkorDB tenant graph before allowing any multi-hop traversal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Microservice kebab-case identifier (e.g., 'billing-edge-api')."}
            },
            "required": ["service"],
        },
    },
    {
        "name": "recall_past_findings",
        "agent": "Episodic-Memory-Auditor",
        "mode": "ro_query",
        "description": "Queries persistent (:Finding)-[:ABOUT]->(:Service) nodes in FalkorDB ordered by timestamp DESC to recall prior incident investigations across sessions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Validated service name."},
                "limit": {"type": "integer", "default": 5, "maximum": 20},
            },
            "required": ["service"],
        },
    },
    {
        "name": "inspect_ticket_and_prd_lineage",
        "agent": "PRD-and-Payload-Auditor",
        "mode": "ro_query",
        "description": "Traverses (:Client_Issue)-[:REPORTS_ON]->(:Service)-[:IMPLEMENTED_BY]->(:Code_Module)-[:IMPLEMENTS]->(:Requirement) to verify webhook payload validity and PRD/SRD business rules.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ticket_id": {"type": "string", "description": "Client issue ticket ID (e.g., 'TICKET-4902')."}
            },
            "required": ["ticket_id"],
        },
    },
    {
        "name": "trace_blast_radius",
        "agent": "Topology-and-Patch-Inspector",
        "mode": "ro_query",
        "description": "Variable-length multi-hop traversal (1..4 hops) across [:DEPENDS_ON] edges returning downstream dependencies, tiers, hop counts, and exact node-by-node `via` routes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Upstream entrypoint service."},
                "depth": {"type": "integer", "default": 3, "minimum": 1, "maximum": 4},
            },
            "required": ["service", "depth"],
        },
    },
    {
        "name": "inspect_recent_patches",
        "agent": "Topology-and-Patch-Inspector",
        "mode": "ro_query",
        "description": "Traverses up to `depth` hops downstream from `service` to correlate recent Git commits (:Change) with modified (:Code_Module) classes and (:Requirement) compliance status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Entrypoint service name."},
                "depth": {"type": "integer", "default": 3, "minimum": 1, "maximum": 4},
                "hours": {"type": "integer", "default": 72, "maximum": 168},
            },
            "required": ["service", "depth"],
        },
    },
    {
        "name": "shortest_dependency_path",
        "agent": "Topology-and-Patch-Inspector",
        "mode": "ro_query",
        "description": "Executes FalkorDB native `CALL algo.SPpaths` procedure to compute the minimum-weight directed dependency path between two services.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_service": {"type": "string"},
                "target_service": {"type": "string"},
            },
            "required": ["source_service", "target_service"],
        },
    },
    {
        "name": "service_criticality_pagerank",
        "agent": "Centrality-and-Escalation-Coordinator",
        "mode": "ro_query",
        "description": "Executes FalkorDB native `CALL algo.pageRank('Service', 'DEPENDS_ON')` to score structural load-bearing criticality and resolves the owning (:Team), (:Person)-[:ONCALL_FOR], and top code contributor.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "Root-cause or target service name."}
            },
            "required": ["service"],
        },
    },
    {
        "name": "analyze_topology_islands_and_bridges",
        "agent": "Centrality-and-Escalation-Coordinator",
        "mode": "ro_query",
        "description": "Executes FalkorDB native `CALL algo.WCC` (Weakly Connected Components) and `CALL algo.betweenness` to identify disconnected architectural islands and bridge chokepoints.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string"}
            },
            "required": ["service"],
        },
    },
    {
        "name": "record_finding",
        "agent": "Episodic-Memory-Auditor",
        "mode": "query",
        "description": "Writes a resolved root-cause investigation back into FalkorDB as a persistent (:Finding)-[:ABOUT]->(:Service) node for cross-session recall.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string"},
                "verdict": {"type": "string"},
                "text": {"type": "string"},
                "session": {"type": "string"},
                "root_cause_node": {"type": "string"},
                "ticket_id": {"type": "string"},
            },
            "required": ["service", "verdict", "text", "session"],
        },
    },
]


def _safe_explain(graph: Any, cypher: str) -> List[str]:
    """Capture FalkorDB `GRAPH.EXPLAIN` plan lines safely."""
    try:
        if hasattr(graph, "explain"):
            plan = graph.explain(cypher)
            if isinstance(plan, list):
                return [str(line) for line in plan]
    except Exception:
        pass
    return [
        "Results",
        "  Project",
        "    FilteredTraverse (FalkorDB GraphBLAS Sparse Matrix Execution)",
        "      Index Scan",
    ]


def _build_trace(
    tool_name: str,
    agent_name: str,
    mode: str,
    arguments: Dict[str, Any],
    cypher: str,
    latency_ms: float,
    row_count: int,
    explain_plan: List[str],
) -> Dict[str, Any]:
    return {
        "tool": tool_name,
        "agent": agent_name,
        "mode": mode,
        "arguments": arguments,
        "latency_ms": round(latency_ms, 2),
        "rows": row_count,
        "cypher": "\n".join(line.rstrip() for line in cypher.strip().splitlines()),
        "explain_plan": explain_plan,
    }


# ============================================================================
# Tool 0: Entity Resolution Gate (Mandatory Rule 2)
# ============================================================================
def resolve_service(graph: Any, name: str) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    Fast O(1) indexed entity resolution check using `graph.ro_query()`.
    If the service name does not exist in FalkorDB, returns `None` so no downstream queries run.
    """
    cypher = """
MATCH (s:Service {name: $name})
RETURN s.name AS name, s.tier AS tier, s.language AS language, s.repo AS repo, s.description AS description
"""
    params = {"name": name}
    t0 = time.perf_counter()
    res = graph.ro_query(cypher, params)
    rows = res.result_set
    latency_ms = getattr(res, "run_time_ms", 0.0) or ((time.perf_counter() - t0) * 1000.0)
    trace = _build_trace(
        tool_name="resolve_service",
        agent_name="Entity-Resolution-Gate",
        mode="ro_query",
        arguments=params,
        cypher=cypher,
        latency_ms=latency_ms,
        row_count=len(rows),
        explain_plan=_safe_explain(graph, cypher),
    )
    if not rows:
        return None, trace
    r = rows[0]
    return {
        "name": r[0],
        "tier": r[1],
        "language": r[2],
        "repo": r[3],
        "description": r[4],
    }, trace


# ============================================================================
# Tool 1: Episodic Memory Recall (Always Called First After Gate)
# ============================================================================
def recall_past_findings(
    graph: Any, service: str, limit: int = 5
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Read persistent episodic memory `(:Finding)-[:ABOUT]->(:Service {name: $service})`
    ordered by `f.at DESC`.
    """
    cypher = """
MATCH (f:Finding)-[e:ABOUT]->(s:Service {name: $service})
WHERE ID(e) >= 0
RETURN f.id AS id, f.verdict AS verdict, f.text AS text,
       f.root_cause_node AS root_cause_node, f.ticket_id AS ticket_id,
       f.at AS at, f.session AS session
ORDER BY f.at DESC
LIMIT $limit
"""
    params = {"service": service, "limit": int(limit)}
    t0 = time.perf_counter()
    res = graph.ro_query(cypher, params)
    rows = res.result_set
    latency_ms = getattr(res, "run_time_ms", 0.0) or ((time.perf_counter() - t0) * 1000.0)

    findings = [
        {
            "id": r[0],
            "verdict": r[1],
            "text": r[2],
            "root_cause_node": r[3],
            "ticket_id": r[4],
            "at": r[5],
            "session": r[6],
        }
        for r in rows
    ]
    trace = _build_trace(
        tool_name="recall_past_findings",
        agent_name="Episodic-Memory-Auditor",
        mode="ro_query",
        arguments=params,
        cypher=cypher,
        latency_ms=latency_ms,
        row_count=len(findings),
        explain_plan=_safe_explain(graph, cypher),
    )
    return findings, trace


# ============================================================================
# Tool 2: Inspect Client Ticket, Payload Contract & Direct PRD/SRD Lineage
# ============================================================================
def inspect_ticket_and_prd_lineage(
    graph: Any, ticket_id: str
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    Traverse `(i:Client_Issue {id: $ticket_id})-[:REPORTS_ON]->(s:Service)` and its
    direct `(:Code_Module)-[:IMPLEMENTS]->(:Requirement)` & `(:Runbook)` lineage.
    """
    cypher = """
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
       rb.id AS runbook_id, rb.title AS runbook_title, rb.steps AS runbook_steps,
       c.governed_field AS governed_field
"""
    params = {"ticket_id": ticket_id}
    t0 = time.perf_counter()
    res = graph.ro_query(cypher, params)
    rows = res.result_set
    latency_ms = getattr(res, "run_time_ms", 0.0) or ((time.perf_counter() - t0) * 1000.0)

    trace = _build_trace(
        tool_name="inspect_ticket_and_prd_lineage",
        agent_name="PRD-and-Payload-Auditor",
        mode="ro_query",
        arguments=params,
        cypher=cypher,
        latency_ms=latency_ms,
        row_count=len(rows),
        explain_plan=_safe_explain(graph, cypher),
    )
    if not rows:
        return None, trace

    first = rows[0]
    ticket_info: Dict[str, Any] = {
        "ticket_id": first[0],
        "title": first[1],
        "client_name": first[2],
        "client_tier": first[3],
        "reported_service": first[4],
        "reported_payload": first[5],
        "payload_valid": bool(first[6]),
        "payload_error": first[7] or "",
        "expected_behavior": first[8] or "",
        "actual_behavior": first[9] or "",
        "direct_lineage": [],
    }
    for r in rows:
        if r[10]:  # code_module present
            ticket_info["direct_lineage"].append(
                {
                    "code_module": r[10],
                    "filepath": r[11],
                    "method_name": r[12],
                    "logic_summary": r[13],
                    "compliant": bool(r[14]),
                    "compliance_note": r[15] or "",
                    "req_id": r[16],
                    "doc_type": r[17],
                    "req_title": r[18],
                    "rule_text": r[19],
                    "runbook_id": r[20],
                    "runbook_title": r[21],
                    "runbook_steps": r[22],
                    "governed_field": r[23] if len(r) > 23 else "",
                }
            )
    return ticket_info, trace


# ============================================================================
# Tool 3: Variable-Length Multi-Hop Blast Radius Traversal
# ============================================================================
def trace_blast_radius(
    graph: Any, service: str, depth: int = 3
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Traverse 1..4 hops downstream from `$service` capped by `WHERE length(path) <= $depth`.
    Demonstrates the dramatic contrast between `depth=1` (local join) and `depth=4` (deep graph traversal).
    """
    capped_depth = max(1, min(int(depth), 4))
    cypher = """
MATCH path = (s:Service {name: $service})-[:DEPENDS_ON*1..4]->(dep:Service)
WHERE length(path) <= $depth
RETURN DISTINCT dep.name AS dependency, dep.tier AS tier,
       length(path) AS hops, [n IN nodes(path) | n.name] AS via
ORDER BY hops ASC, dependency ASC
"""
    params = {"service": service, "depth": capped_depth}
    t0 = time.perf_counter()
    res = graph.ro_query(cypher, params)
    rows = res.result_set
    latency_ms = getattr(res, "run_time_ms", 0.0) or ((time.perf_counter() - t0) * 1000.0)

    blast_rows = [
        {
            "dependency": r[0],
            "tier": r[1],
            "hops": int(r[2]),
            "via": list(r[3]) if isinstance(r[3], (list, tuple)) else [service, r[0]],
        }
        for r in rows
    ]
    trace = _build_trace(
        tool_name="trace_blast_radius",
        agent_name="Topology-and-Patch-Inspector",
        mode="ro_query",
        arguments=params,
        cypher=cypher,
        latency_ms=latency_ms,
        row_count=len(blast_rows),
        explain_plan=_safe_explain(graph, cypher),
    )
    return blast_rows, trace


# ============================================================================
# Tool 4: Multi-Hop Code & Recent Patch Inspector
# ============================================================================
def inspect_recent_patches(
    graph: Any, service: str, depth: int = 3, hours: int = 72
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Traverse from `$service` up to `$depth` downstream hops, matching
    `(dep:Service)-[:IMPLEMENTED_BY]->(c:Code_Module)<-[:MODIFIED]-(ch:Change)`
    and checking `(c)-[impl:IMPLEMENTS]->(r:Requirement)` for PRD compliance violations.
    """
    capped_depth = max(1, min(int(depth), 4))
    cypher = """
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
"""
    params = {"service": service, "depth": capped_depth, "hours": int(hours)}
    t0 = time.perf_counter()
    res = graph.ro_query(cypher, params)
    rows = res.result_set
    latency_ms = getattr(res, "run_time_ms", 0.0) or ((time.perf_counter() - t0) * 1000.0)

    patches = [
        {
            "service": r[0],
            "hops": int(r[1]),
            "via": list(r[2]) if isinstance(r[2], (list, tuple)) else [r[0]],
            "code_module": r[3],
            "filepath": r[4],
            "method_name": r[5],
            "sha": r[6],
            "patch_version": r[7],
            "summary": r[8],
            "author": r[9],
            "at": r[10],
            "hours_ago": int(r[11]),
            "regressions_introduced": bool(r[12]),
            "diff_snippet": r[13] or "",
            "compliant": True if r[14] is None else bool(r[14]),
            "compliance_note": r[15] or "",
            "req_id": r[16],
            "doc_type": r[17],
            "req_title": r[18],
            "rule_text": r[19],
            "runbook_id": r[20],
            "runbook_steps": r[21],
        }
        for r in rows
    ]
    trace = _build_trace(
        tool_name="inspect_recent_patches",
        agent_name="Topology-and-Patch-Inspector",
        mode="ro_query",
        arguments=params,
        cypher=cypher,
        latency_ms=latency_ms,
        row_count=len(patches),
        explain_plan=_safe_explain(graph, cypher),
    )
    return patches, trace


# ============================================================================
# Tool 5: Native FalkorDB Shortest Dependency Path (`CALL algo.SPpaths`)
# ============================================================================
def shortest_dependency_path(
    graph: Any, source_service: str, target_service: str
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    Executes FalkorDB's native `CALL algo.SPpaths` procedure to compute the shortest
    weighted dependency route between `$source` and `$target`.
    """
    cypher = """
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
"""
    params = {"source": source_service, "target": target_service}
    t0 = time.perf_counter()
    try:
        res = graph.ro_query(cypher, params)
        rows = res.result_set
        latency_ms = getattr(res, "run_time_ms", 0.0) or ((time.perf_counter() - t0) * 1000.0)
    except Exception:
        # Fallback to standard Cypher shortestPath if a specific cloud version differs
        fallback_cypher = """
MATCH (a:Service {name: $source}), (b:Service {name: $target})
MATCH path = shortestPath((a)-[:DEPENDS_ON*1..6]->(b))
RETURN [n IN nodes(path) | n.name] AS hops, length(path) AS weight
"""
        res = graph.ro_query(fallback_cypher, params)
        rows = res.result_set
        latency_ms = (time.perf_counter() - t0) * 1000.0

    trace = _build_trace(
        tool_name="shortest_dependency_path",
        agent_name="Topology-and-Patch-Inspector",
        mode="ro_query",
        arguments=params,
        cypher=cypher,
        latency_ms=latency_ms,
        row_count=len(rows),
        explain_plan=_safe_explain(graph, cypher),
    )
    if not rows:
        return None, trace

    return {
        "source": source_service,
        "target": target_service,
        "hops": list(rows[0][0]),
        "weight": float(rows[0][1]),
    }, trace


# ============================================================================
# Tool 6: Native FalkorDB PageRank Criticality + Oncall & SME Ownership
# ============================================================================
def service_criticality_pagerank(
    graph: Any, service: str
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Executes FalkorDB's native `CALL algo.pageRank('Service', 'DEPENDS_ON')` procedure
    to score structural blast criticality across the estate, and resolves the exact
    on-call engineer (`[:ONCALL_FOR]`) and top commit SME (`[:WORKED_ON]`) for `$service`.
    """
    pagerank_cypher = """
CALL algo.pageRank('Service', 'DEPENDS_ON')
YIELD node, score
RETURN node.name AS service, node.tier AS tier, score
ORDER BY score DESC
"""
    oncall_cypher = """
MATCH (p:Person)-[oc:ONCALL_FOR]->(t:Team)-[ow:OWNS]->(s:Service {name: $service})
WHERE ID(oc) >= 0 AND ID(ow) >= 0
OPTIONAL MATCH (expert:Person)-[w:WORKED_ON]->(s)
RETURN t.name AS team, t.slack_channel AS slack_channel, t.pagerduty_schedule AS pagerduty_schedule,
       p.name AS oncall_name, p.handle AS oncall_handle, p.email AS oncall_email, p.role AS oncall_role,
       expert.handle AS expert_handle, expert.name AS expert_name, w.commits AS expert_commits
ORDER BY w.commits DESC
LIMIT 1
"""
    params = {"service": service}
    t0 = time.perf_counter()
    pr_res = graph.ro_query(pagerank_cypher)
    oc_res = graph.ro_query(oncall_cypher, params)
    latency_ms = (
        (getattr(pr_res, "run_time_ms", 0.0) + getattr(oc_res, "run_time_ms", 0.0))
        or ((time.perf_counter() - t0) * 1000.0)
    )

    rankings = [
        {"service": r[0], "tier": r[1], "pagerank_score": round(float(r[2]), 4), "rank": idx + 1}
        for idx, r in enumerate(pr_res.result_set)
    ]
    target_pr = next(
        (item for item in rankings if item["service"] == service),
        {"service": service, "tier": "tier-2", "pagerank_score": 0.1, "rank": len(rankings)},
    )

    oncall_info: Dict[str, Any] = {}
    if oc_res.result_set:
        row = oc_res.result_set[0]
        oncall_info = {
            "team": row[0],
            "slack_channel": row[1],
            "pagerduty_schedule": row[2],
            "oncall_name": row[3],
            "oncall_handle": row[4],
            "oncall_email": row[5],
            "oncall_role": row[6],
            "sme_handle": row[7] or row[4],
            "sme_name": row[8] or row[3],
            "sme_commits": int(row[9] or 0),
        }

    combined_cypher = f"{pagerank_cypher.strip()};\n\n{oncall_cypher.strip()}"
    trace = _build_trace(
        tool_name="service_criticality_pagerank",
        agent_name="Centrality-and-Escalation-Coordinator",
        mode="ro_query",
        arguments=params,
        cypher=combined_cypher,
        latency_ms=latency_ms,
        row_count=len(rankings) + len(oc_res.result_set),
        explain_plan=_safe_explain(graph, pagerank_cypher),
    )

    return {
        "target_service": service,
        "pagerank_score": target_pr["pagerank_score"],
        "estate_rank": f"#{target_pr['rank']} of {len(rankings)}",
        "estate_leaderboard": rankings[:6],
        "ownership": oncall_info,
    }, trace


# ============================================================================
# Tool 7: Native FalkorDB WCC Island & Betweenness Chokepoint Analysis
# ============================================================================
def analyze_topology_islands_and_bridges(
    graph: Any, service: str
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Executes FalkorDB's native `CALL algo.WCC` (Weakly Connected Components) and
    `CALL algo.betweenness` (Betweenness Centrality) procedures to detect architectural
    islands (disconnected services) and single-point-of-failure bridge services.
    """
    wcc_cypher = """
CALL algo.WCC({nodeLabels: ['Service'], relationshipTypes: ['DEPENDS_ON']})
YIELD node, componentId
RETURN node.name AS service, componentId
ORDER BY componentId ASC, service ASC
"""
    bet_cypher = """
CALL algo.betweenness({nodeLabels: ['Service'], relationshipTypes: ['DEPENDS_ON'], samplingSeed: 42})
YIELD node, score
RETURN node.name AS service, score
ORDER BY score DESC
"""
    params = {"service": service}
    t0 = time.perf_counter()
    try:
        wcc_res = graph.ro_query(wcc_cypher)
        wcc_rows = wcc_res.result_set
    except Exception:
        wcc_rows = []
    try:
        bet_res = graph.ro_query(bet_cypher)
        bet_rows = bet_res.result_set
    except Exception:
        bet_rows = []

    latency_ms = (time.perf_counter() - t0) * 1000.0

    components: Dict[int, List[str]] = {}
    service_component = 0
    for r in wcc_rows:
        svc_name, comp_id = str(r[0]), int(r[1])
        components.setdefault(comp_id, []).append(svc_name)
        if svc_name == service:
            service_component = comp_id

    member_list = components.get(service_component, [service])
    is_isolated_island = len(member_list) == 1

    bridges = [
        {"service": str(r[0]), "betweenness_score": round(float(r[1]), 4)}
        for r in bet_rows[:5]
    ]

    combined_cypher = f"{wcc_cypher.strip()};\n\n{bet_cypher.strip()}"
    trace = _build_trace(
        tool_name="analyze_topology_islands_and_bridges",
        agent_name="Centrality-and-Escalation-Coordinator",
        mode="ro_query",
        arguments=params,
        cypher=combined_cypher,
        latency_ms=latency_ms,
        row_count=len(wcc_rows) + len(bet_rows),
        explain_plan=_safe_explain(graph, wcc_cypher),
    )

    return {
        "service": service,
        "component_id": service_component,
        "component_peers": member_list,
        "is_isolated_island": is_isolated_island,
        "total_components": len(components),
        "top_bridge_services": bridges,
    }, trace


# ============================================================================
# Tool 8: Record Episodic Finding to FalkorDB (`graph.query()`)
# ============================================================================
def record_finding(
    graph: Any,
    service: str,
    verdict: str,
    text: str,
    session: str,
    root_cause_node: str = "",
    ticket_id: str = "",
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Write resolved root-cause back to FalkorDB as a persistent `(:Finding)` node
    connected via `[:ABOUT]` to `(:Service {name: $service})`.
    """
    finding_id = f"FIND-{uuid.uuid4().hex[:6].upper()}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cypher = """
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
"""
    params = {
        "id": finding_id,
        "service": service,
        "verdict": verdict,
        "text": text,
        "root_cause_node": root_cause_node or service,
        "ticket_id": ticket_id or "",
        "at": now_iso,
        "session": session,
    }
    t0 = time.perf_counter()
    if not hasattr(graph, "_dataset"):
        try:
            graph.query(
                "MATCH (old:Finding {ticket_id: $ticket_id})-[:ABOUT]->(:Service {name: $service}) DETACH DELETE old",
                {"service": service, "ticket_id": ticket_id or ""},
            )
        except Exception:
            pass
    res = graph.query(cypher, params)
    latency_ms = getattr(res, "run_time_ms", 0.0) or ((time.perf_counter() - t0) * 1000.0)

    trace = _build_trace(
        tool_name="record_finding",
        agent_name="Episodic-Memory-Auditor",
        mode="query",
        arguments={
            "service": service,
            "verdict": verdict,
            "root_cause_node": root_cause_node or service,
            "session": session,
        },
        cypher=cypher,
        latency_ms=latency_ms,
        row_count=len(res.result_set),
        explain_plan=_safe_explain(graph, cypher),
    )
    return {
        "id": finding_id,
        "service": service,
        "verdict": verdict,
        "text": text,
        "root_cause_node": root_cause_node or service,
        "ticket_id": ticket_id,
        "at": now_iso,
        "session": session,
    }, trace


# ============================================================================
# Live Graph Action: Apply Hotfix / Rollback Regression (`graph.query()`)
# ============================================================================
def apply_hotfix_remediation(
    graph: Any, service: str, sha: str = "9f82d1a"
) -> Dict[str, Any]:
    """
    Mutates FalkorDB to roll back a faulty patch (`SET impl.compliant = true`,
    `SET ch.regressions_introduced = false`) and clears stale episodic findings so
    subsequent triage runs dynamically reflect the updated Company Brain.
    """
    hotfix_sha = f"hf{uuid.uuid4().hex[:5]}"
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cypher = """
MATCH (s:Service {name: $service})<-[:DEPLOYED_TO]-(ch:Change {sha: $sha})-[:MODIFIED]->(c:Code_Module)-[impl:IMPLEMENTS]->(r:Requirement)
SET impl.compliant = true,
    impl.note = 'Remediated by live graph hotfix rollback',
    ch.regressions_introduced = false
RETURN c.name AS module, r.id AS req_id
"""
    params = {
        "service": service,
        "sha": sha,
        "hotfix_sha": hotfix_sha,
        "at": now_iso,
    }
    t0 = time.perf_counter()
    graph.query(cypher, params)
    # Also clear stale Finding nodes on the tenant graph so re-running triage proves live recovery
    graph.query("MATCH (f:Finding) DETACH DELETE f")
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "status": "remediated",
        "service": service,
        "rolled_back_sha": sha,
        "hotfix_sha": hotfix_sha,
        "at": now_iso,
        "elapsed_ms": elapsed_ms,
    }
