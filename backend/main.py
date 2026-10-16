"""
FastAPI Backend Application for FalkorTrace (`backend/main.py`).

Serves:
- `GET /`: Interactive 3-Pane Dark-Mode Operations Dashboard (`frontend/index.html`)
- `GET /api/health`: FalkorDB connection & multigraph status
- `POST /api/config/falkordb`: Live runtime connection switcher (Local Docker / FalkorDB Cloud)
- `GET /api/graph`: Complete graph topology (nodes + directed edges) for visualization
- `POST /api/triage`: Multi-Agent Triage Swarm execution
- `POST /api/seed`: Idempotent tenant graph reset/re-seed
- `POST /api/memory/clear`: Episodic (:Finding) memory reset
- `POST /api/remediate`: Live Graph Hotfix / Patch Rollback action
- `GET /api/mcp/tools` & `POST /api/mcp/call`: Model Context Protocol endpoints
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from backend.agent import resolve_natural_language_query, run_multi_agent_triage
from backend.db import ensure_tenant_seeded, get_db, get_live_dataset_snapshot
from backend.mcp_server import call_mcp_tool, list_mcp_tools
from backend.seed import TENANT_METADATA, seed_tenant
from backend.tools import apply_hotfix_remediation, recall_past_findings


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    db = get_db()
    for tid in ("killbill-prod", "nexus-commerce"):
        ensure_tenant_seeded(db, tid)
    yield


app = FastAPI(
    title="FalkorTrace — Multi-Agent Graph Triage & Company Brain",
    description="Powered by FalkorDB Multigraphs, Parameterized Cypher, Native Graph Algorithms (SPpaths, PageRank, WCC, Betweenness), and MCP.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_HTML_PATH = Path(__file__).resolve().parent.parent / "frontend" / "index.html"


# ============================================================================
# Request / Response Models
# ============================================================================
class TriageRequest(BaseModel):
    tenant_id: str = Field(default="killbill-prod")
    service: str = Field(default="billing-edge-api")
    ticket_id: Optional[str] = Field(default=None)
    depth: int = Field(default=4, ge=1, le=4)
    bypass_memory: bool = Field(default=False)
    session_id: Optional[str] = Field(default=None)


class AskRequest(BaseModel):
    question: str
    tenant_id: str = Field(default="killbill-prod")
    depth: int = Field(default=4, ge=1, le=4)
    bypass_memory: bool = Field(default=False)


class SeedRequest(BaseModel):
    tenant_id: str = Field(default="killbill-prod")


class MemoryClearRequest(BaseModel):
    tenant_id: str = Field(default="killbill-prod")


class RemediateRequest(BaseModel):
    tenant_id: str = Field(default="killbill-prod")
    service: str = Field(default="proration-engine")
    sha: str = Field(default="9f82d1a")


class FalkorDBConfigRequest(BaseModel):
    host: str = Field(default="localhost")
    port: int = Field(default=6379)
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    ssl: bool = Field(default=False)


class MCPCallRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = Field(default="killbill-prod")


# ============================================================================
# REST Endpoints
# ============================================================================
@app.get("/", response_class=HTMLResponse)
def serve_dashboard() -> Any:
    if not FRONTEND_HTML_PATH.exists():
        return HTMLResponse("<h1>FalkorTrace Frontend Not Found</h1>", status_code=404)
    return FileResponse(FRONTEND_HTML_PATH)


@app.get("/api/health")
def health_check() -> Dict[str, Any]:
    db = get_db()
    return {
        "status": "ok",
        "falkordb": db.status(),
        "tenants": TENANT_METADATA,
        "mcp_tools_count": len(list_mcp_tools()),
    }


@app.post("/api/config/falkordb")
def update_falkordb_connection(req: FalkorDBConfigRequest) -> Dict[str, Any]:
    db = get_db()
    status = db.reconfigure(
        host=req.host,
        port=req.port,
        username=req.username,
        password=req.password,
        ssl=req.ssl,
    )
    for tid in ("killbill-prod", "nexus-commerce"):
        ensure_tenant_seeded(db, tid)
    return {"status": "reconfigured", "falkordb": status}


@app.get("/api/graph")
def get_tenant_graph(tenant_id: str = Query(default="killbill-prod")) -> Dict[str, Any]:
    """
    Returns all nodes and relationships for `falkortrace:{tenant_id}` to power the
    interactive 2D Force/Layered SVG Graph Visualizer in the center pane.
    Includes the automatic `ensure_tenant_seeded` guard for Cloud Free Tier resilience
    and queries live FalkorDB state via `get_live_dataset_snapshot`.
    """
    db = get_db()
    seed_status = ensure_tenant_seeded(db, tenant_id)
    graph_name = f"falkortrace:{tenant_id}"
    graph = db.select_graph(graph_name)

    # Read current dataset state (reflecting any live findings or hotfixes on both embedded and live FalkorDB)
    ds = get_live_dataset_snapshot(graph, tenant_id)

    # Also query live findings from FalkorDB
    live_findings: List[Dict[str, Any]] = []
    for svc in ds["services"]:
        f_list, _ = recall_past_findings(graph, svc["name"], limit=5)
        for f in f_list:
            f["service"] = svc["name"]
            live_findings.append(f)

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for issue in ds["client_issues"]:
        nodes.append(
            {
                "id": issue["id"],
                "label": issue["id"],
                "type": "Client_Issue",
                "subtitle": issue["client_name"],
                "valid": issue["payload_valid"],
                "data": issue,
            }
        )
        edges.append(
            {
                "from": issue["id"],
                "to": issue["reported_service"],
                "label": "REPORTS_ON",
            }
        )

    for svc in ds["services"]:
        nodes.append(
            {
                "id": svc["name"],
                "label": svc["name"],
                "type": "Service",
                "subtitle": svc["tier"],
                "data": svc,
            }
        )

    for dep in ds["dependencies"]:
        edges.append(
            {
                "from": dep["upstream"],
                "to": dep["downstream"],
                "label": f"DEPENDS_ON (w={dep['weight']})",
                "kind": dep["kind"],
                "weight": dep["weight"],
            }
        )

    for mod in ds["code_modules"]:
        nodes.append(
            {
                "id": mod["name"],
                "label": mod["name"],
                "type": "Code_Module",
                "subtitle": mod["method_name"],
                "data": mod,
            }
        )
        edges.append(
            {
                "from": mod["service"],
                "to": mod["name"],
                "label": "IMPLEMENTED_BY",
            }
        )

    for req in ds["requirements"]:
        nodes.append(
            {
                "id": req["id"],
                "label": req["id"],
                "type": "Requirement",
                "subtitle": f"{req['doc_type']}: {req['title'][:26]}",
                "data": req,
            }
        )

    for im in ds["implements_edges"]:
        edges.append(
            {
                "from": im["module"],
                "to": im["requirement"],
                "label": "IMPLEMENTS" if im["compliant"] else "VIOLATES (!)",
                "compliant": im["compliant"],
            }
        )

    for ch in ds["changes"]:
        nodes.append(
            {
                "id": ch["sha"],
                "label": f"{ch['patch_version']} ({ch['sha']})",
                "type": "Change",
                "subtitle": f"{ch['author']} ({ch['hours_ago']}h ago)",
                "regression": ch["regressions_introduced"],
                "data": ch,
            }
        )
        edges.append({"from": ch["sha"], "to": ch["modified_module"], "label": "MODIFIED"})
        edges.append({"from": ch["sha"], "to": ch["deployed_service"], "label": "DEPLOYED_TO"})

    for team in ds["teams"]:
        nodes.append(
            {
                "id": team["name"],
                "label": team["name"],
                "type": "Team",
                "subtitle": team["slack_channel"],
                "data": team,
            }
        )
        for owned in team["owned_services"]:
            edges.append({"from": team["name"], "to": owned, "label": "OWNS"})

    for p in ds["people"]:
        if p.get("oncall"):
            nodes.append(
                {
                    "id": p["handle"],
                    "label": p["handle"],
                    "type": "Person",
                    "subtitle": p["name"],
                    "data": p,
                }
            )
            edges.append({"from": p["handle"], "to": p["team"], "label": "ONCALL_FOR"})

    for rb in ds.get("runbooks", []):
        nodes.append(
            {
                "id": rb["id"],
                "label": rb["id"],
                "type": "Runbook",
                "subtitle": rb["title"][:26],
                "data": rb,
            }
        )
        edges.append({"from": rb["id"], "to": rb["requirement_id"], "label": "REMEDIATES"})

    for f in live_findings:
        nodes.append(
            {
                "id": f["id"],
                "label": f["id"],
                "type": "Finding",
                "subtitle": f"Memory: {f['verdict']}",
                "data": f,
            }
        )
        edges.append({"from": f["id"], "to": f["service"], "label": "ABOUT"})

    return {
        "tenant_id": tenant_id,
        "graph_name": graph_name,
        "tenant_meta": TENANT_METADATA.get(tenant_id, {}),
        "seed_status": seed_status,
        "falkordb": db.status(),
        "nodes": nodes,
        "edges": edges,
        "services": [s["name"] for s in ds["services"]],
        "tickets": ds["client_issues"],
        "findings": live_findings,
    }


@app.post("/api/triage")
def execute_triage(req: TriageRequest) -> Dict[str, Any]:
    return run_multi_agent_triage(
        tenant_id=req.tenant_id,
        service=req.service,
        ticket_id=req.ticket_id,
        depth=req.depth,
        bypass_memory=req.bypass_memory,
        session_id=req.session_id,
    )


@app.post("/api/ask")
def execute_ask(req: AskRequest) -> Dict[str, Any]:
    return resolve_natural_language_query(
        question=req.question,
        tenant_id=req.tenant_id,
        depth=req.depth,
        bypass_memory=req.bypass_memory,
    )


@app.post("/api/compare-depth")
def compare_depth_triage(req: TriageRequest) -> Dict[str, Any]:
    """
    Runs Depth=1 (Shallow Horizon) vs. Depth=4 (Full Multi-Hop Horizon) side-by-side
    so judges can visually inspect why variable-length graph traversal `[:DEPENDS_ON*1..4]`
    is essential to catch deep downstream regressions.
    """
    shallow = run_multi_agent_triage(
        tenant_id=req.tenant_id,
        service=req.service,
        ticket_id=req.ticket_id,
        depth=1,
        bypass_memory=True,
    )
    deep = run_multi_agent_triage(
        tenant_id=req.tenant_id,
        service=req.service,
        ticket_id=req.ticket_id,
        depth=4,
        bypass_memory=True,
    )
    return {
        "tenant_id": req.tenant_id,
        "service": req.service,
        "ticket_id": deep.get("ticket_id"),
        "shallow_depth_1": shallow,
        "deep_depth_4": deep,
    }


@app.post("/api/seed")
def reseed_tenant_graph(req: SeedRequest) -> Dict[str, Any]:
    db = get_db()
    return seed_tenant(db, req.tenant_id)


@app.post("/api/memory/clear")
def clear_tenant_memory(req: MemoryClearRequest) -> Dict[str, Any]:
    db = get_db()
    graph_name = f"falkortrace:{req.tenant_id}"
    graph = db.select_graph(graph_name)
    graph.query("MATCH (f:Finding) DETACH DELETE f")
    return {
        "status": "cleared",
        "tenant_id": req.tenant_id,
        "graph_name": graph_name,
    }


@app.post("/api/remediate")
def remediate_patch_regression(req: RemediateRequest) -> Dict[str, Any]:
    db = get_db()
    ensure_tenant_seeded(db, req.tenant_id)
    graph = db.select_graph(f"falkortrace:{req.tenant_id}")
    return apply_hotfix_remediation(graph, service=req.service, sha=req.sha)


@app.get("/api/mcp/tools")
def get_mcp_tools() -> Dict[str, Any]:
    return {"tools": list_mcp_tools()}


@app.post("/api/mcp/call")
def invoke_mcp_tool(req: MCPCallRequest) -> Dict[str, Any]:
    try:
        return call_mcp_tool(req.tool_name, req.arguments, tenant_id=req.tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

