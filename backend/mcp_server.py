"""
Model Context Protocol (MCP) Server for FalkorTrace (`backend/mcp_server.py`).

Exposes FalkorTrace's fixed parameterized Cypher & native Graph Algorithm tools over:
1. JSON-RPC 2.0 `stdio` transport (`python -m backend.mcp_server`) for Claude Desktop, Cursor, or Antigravity.
2. Direct Python functions (`list_mcp_tools`, `call_mcp_tool`) mounted on FastAPI (`/api/mcp/tools`, `/api/mcp/call`).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from backend.db import ensure_tenant_seeded, get_db
from backend.tools import (
    MCP_TOOLS_CATALOGUE,
    analyze_topology_islands_and_bridges,
    inspect_recent_patches,
    inspect_ticket_and_prd_lineage,
    recall_past_findings,
    record_finding,
    resolve_service,
    service_criticality_pagerank,
    shortest_dependency_path,
    trace_blast_radius,
)


def list_mcp_tools() -> List[Dict[str, Any]]:
    """Return the MCP-compliant tool schema catalogue."""
    return MCP_TOOLS_CATALOGUE


def call_mcp_tool(
    tool_name: str, arguments: Dict[str, Any], tenant_id: str = "killbill-prod"
) -> Dict[str, Any]:
    """
    Execute a single MCP tool against `db.select_graph(f"falkortrace:{tenant_id}")`.
    Enforces the Entity Resolution Gate (`resolve_service`) before any service-scoped tool runs.
    """
    db = get_db()
    ensure_tenant_seeded(db, tenant_id)
    graph = db.select_graph(f"falkortrace:{tenant_id}")

    if tool_name == "resolve_service":
        data, trace = resolve_service(graph, str(arguments.get("service", "")))
        return {"result": data, "trace": trace}

    # Enforce entity resolution gate on service-scoped tools
    if "service" in arguments and tool_name != "record_finding":
        svc_name = str(arguments["service"])
        resolved, gate_trace = resolve_service(graph, svc_name)
        if resolved is None:
            return {
                "error": f"Unknown service '{svc_name}' — blocked by Entity Resolution Gate.",
                "outcome": "unknown_service",
                "trace": gate_trace,
            }

    if tool_name == "recall_past_findings":
        data, trace = recall_past_findings(
            graph,
            service=str(arguments["service"]),
            limit=int(arguments.get("limit", 5)),
        )
        return {"result": data, "trace": trace}

    if tool_name == "inspect_ticket_and_prd_lineage":
        data, trace = inspect_ticket_and_prd_lineage(
            graph, ticket_id=str(arguments["ticket_id"])
        )
        return {"result": data, "trace": trace}

    if tool_name == "trace_blast_radius":
        data, trace = trace_blast_radius(
            graph,
            service=str(arguments["service"]),
            depth=int(arguments.get("depth", 3)),
        )
        return {"result": data, "trace": trace}

    if tool_name == "inspect_recent_patches":
        data, trace = inspect_recent_patches(
            graph,
            service=str(arguments["service"]),
            depth=int(arguments.get("depth", 3)),
            hours=int(arguments.get("hours", 72)),
        )
        return {"result": data, "trace": trace}

    if tool_name == "shortest_dependency_path":
        data, trace = shortest_dependency_path(
            graph,
            source_service=str(arguments["source_service"]),
            target_service=str(arguments["target_service"]),
        )
        return {"result": data, "trace": trace}

    if tool_name == "service_criticality_pagerank":
        data, trace = service_criticality_pagerank(
            graph, service=str(arguments["service"])
        )
        return {"result": data, "trace": trace}

    if tool_name == "analyze_topology_islands_and_bridges":
        data, trace = analyze_topology_islands_and_bridges(
            graph, service=str(arguments["service"])
        )
        return {"result": data, "trace": trace}

    if tool_name == "record_finding":
        data, trace = record_finding(
            graph,
            service=str(arguments["service"]),
            verdict=str(arguments["verdict"]),
            text=str(arguments["text"]),
            session=str(arguments.get("session", "MCP-SESSION")),
            root_cause_node=str(arguments.get("root_cause_node", "")),
            ticket_id=str(arguments.get("ticket_id", "")),
        )
        return {"result": data, "trace": trace}

    raise ValueError(f"Tool '{tool_name}' is not in the fixed MCP catalogue.")


def run_stdio_mcp_server() -> None:
    """Standard JSON-RPC 2.0 MCP loop over stdin/stdout."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method", "")
            params = req.get("params") or {}

            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "falkortrace-mcp", "version": "1.0.0"},
                        "capabilities": {"tools": {}},
                    },
                }
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"tools": list_mcp_tools()},
                }
            elif method == "tools/call":
                t_name = params.get("name", "")
                t_args = params.get("arguments") or {}
                tenant = t_args.pop("tenant_id", "killbill-prod")
                output = call_mcp_tool(t_name, t_args, tenant_id=tenant)
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(output, indent=2)}]
                    },
                }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }
        except Exception as exc:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32603, "message": str(exc)},
            }
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    run_stdio_mcp_server()
