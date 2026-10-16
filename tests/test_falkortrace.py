"""
End-to-End Pytest Verification Suite for FalkorTrace (`tests/test_falkortrace.py`).

Verifies:
1. Scenario 1 (`TICKET-4902`): Depth=1 misses regression (`WORKING_AS_PER_PRD` with shallow warning) vs Depth=4 catches 3-hop `PATCH_REGRESSION` on `proration-engine` (`FixedAndRecurringInvoiceItemGenerator.java`, `sha:9f82d1a`, `PRD-INV-104`).
2. Cross-Session Episodic Memory Recall (`answered_from_memory` on subsequent query).
3. Scenario 2 (`TICKET-4908`): `WORKING_AS_PER_PRD` on `invoice-orchestrator` (`DiscountPolicyEvaluator.java`, `PRD-DISC-209`, 42 < 50 seats).
4. Scenario 3 (`TICKET-4915`): `DATA_PAYLOAD_ISSUE` on `payment-gateway-router` (`PaymentWebhookValidator.java`, `SRD-PAY-301`, `USDT-ERC20`).
5. Scenario 4A (`legacy-cobol-mainframe`): `unknown_service` blocked at `resolve_service` gate with 1 tool call and 0 rows.
6. Scenario 4B (`audit-vault-archiver`): `not_in_the_graph` detected via WCC island analysis.
7. Multigraph Tenant Isolation (`falkortrace:killbill-prod` vs `falkortrace:nexus-commerce`).
8. Post-Generation Hallucination Guardrail (`accepts()`) rejecting invented service/module names.
9. FastAPI REST & MCP endpoints (`/api/health`, `/api/graph`, `/api/triage`, `/api/remediate`, `/api/mcp/tools`).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.agent import accepts, run_multi_agent_triage
from backend.db import get_db
from backend.main import app
from backend.seed import seed_tenant

client = TestClient(app)


def setup_function() -> None:
    db = get_db()
    seed_tenant(db, "killbill-prod")
    seed_tenant(db, "nexus-commerce")


def test_scenario_1_depth_1_vs_depth_4_and_memory_recall() -> None:
    # 1. At depth=1, Hop-3 proration-engine is out of range -> no regression detected at depth=1
    res_d1 = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        depth=1,
        bypass_memory=True,
    )
    assert res_d1["outcome"] == "answered_with_path"
    assert res_d1["verdict"] == "WORKING_AS_PER_PRD"
    assert "SHALLOW DEPTH=1 WARNING" in res_d1["summary"]

    # 2. At depth=4, traverses 3 hops to proration-engine and catches sha:9f82d1a violating PRD-INV-104
    res_d4 = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        depth=4,
        bypass_memory=True,
    )
    assert res_d4["outcome"] == "answered_with_path"
    assert res_d4["verdict"] == "PATCH_REGRESSION"
    assert res_d4["root_cause_service"] == "proration-engine"
    assert res_d4["citations"]["patch_sha"] == "9f82d1a"
    assert res_d4["citations"]["requirement_id"] == "PRD-INV-104"
    assert res_d4["citations"]["oncall_engineer"] == "@meera-nair"
    assert res_d4["guardrail"]["passed"] is True

    # 3. Subsequent call with bypass_memory=False returns answered_from_memory in 1 step!
    res_mem = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        depth=4,
        bypass_memory=False,
    )
    assert res_mem["outcome"] == "answered_from_memory"
    assert res_mem["verdict"] == "PATCH_REGRESSION"
    assert res_mem["memory_finding"] is not None


def test_scenario_2_working_as_per_prd() -> None:
    res = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="invoice-orchestrator",
        ticket_id="TICKET-4908",
        depth=4,
        bypass_memory=True,
    )
    assert res["outcome"] == "answered_with_path"
    assert res["verdict"] == "WORKING_AS_PER_PRD"
    assert res["citations"]["code_module"] == "DiscountPolicyEvaluator.java"
    assert res["citations"]["requirement_id"] == "PRD-DISC-209"
    assert res["guardrail"]["passed"] is True


def test_scenario_3_data_payload_issue() -> None:
    res = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="payment-gateway-router",
        ticket_id="TICKET-4915",
        depth=4,
        bypass_memory=True,
    )
    assert res["outcome"] == "answered_with_path"
    assert res["verdict"] == "DATA_PAYLOAD_ISSUE"
    assert res["citations"]["code_module"] == "PaymentWebhookValidator.java"
    assert res["citations"]["requirement_id"] == "SRD-PAY-301"
    assert "USDT-ERC20" in res["citations"]["payload_error"]


def test_scenario_4a_unknown_service_gate() -> None:
    res = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="legacy-cobol-mainframe",
        ticket_id=None,
        depth=4,
        bypass_memory=True,
    )
    assert res["outcome"] == "unknown_service"
    assert res["verdict"] == "UNMODELED_OR_UNKNOWN"
    assert len(res["tool_trace"]) == 1
    assert res["tool_trace"][0]["tool"] == "resolve_service"
    assert res["tool_trace"][0]["rows"] == 0


def test_scenario_4b_not_in_the_graph_isolated_island() -> None:
    res = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="audit-vault-archiver",
        ticket_id="TICKET-4920",
        depth=4,
        bypass_memory=True,
    )
    assert res["outcome"] == "not_in_the_graph"
    assert res["verdict"] == "UNMODELED_DEPENDENCY"
    assert res["topology_analysis"]["is_isolated_island"] is True


def test_multigraph_tenant_isolation_and_accepts_guardrail() -> None:
    # Verify nexus-commerce cannot resolve killbill-prod services
    res_cross = run_multi_agent_triage(
        tenant_id="nexus-commerce",
        service="billing-edge-api",
        depth=4,
        bypass_memory=True,
    )
    assert res_cross["outcome"] == "unknown_service"

    # Verify nexus-commerce resolves its own regression
    res_nexus = run_multi_agent_triage(
        tenant_id="nexus-commerce",
        service="checkout-edge-gateway",
        ticket_id="NEXUS-701",
        depth=4,
        bypass_memory=True,
    )
    assert res_nexus["outcome"] == "answered_with_path"
    assert res_nexus["verdict"] == "PATCH_REGRESSION"
    assert res_nexus["root_cause_service"] == "inventory-reservation-engine"

    # Verify accepts() blocks hallucinated kebab-case service names and .java classes
    ok_valid, _ = accepts(
        "Service billing-edge-api connects to proration-engine via invoice-orchestrator.",
        res_nexus | {"services": ["billing-edge-api", "proration-engine", "invoice-orchestrator"], "paths": [], "allowed_tokens": []},
    )
    assert ok_valid is True

    ok_hallucinated, reason = accepts(
        "The failure originated in auth-magic-gateway and SecretBillingHack.java.",
        {"services": ["billing-edge-api"], "paths": [["billing-edge-api"]], "allowed_tokens": ["billing-edge-api"]},
    )
    assert ok_hallucinated is False
    assert "auth-magic-gateway" in reason


def test_fastapi_and_live_hotfix_remediation_endpoints() -> None:
    health = client.get("/api/health").json()
    assert health["status"] == "ok"
    assert health["mcp_tools_count"] == 9

    graph_resp = client.get("/api/graph?tenant_id=killbill-prod").json()
    assert len(graph_resp["nodes"]) > 20
    assert len(graph_resp["edges"]) > 20

    # Apply live graph hotfix rollback on proration-engine sha:9f82d1a
    rem_resp = client.post(
        "/api/remediate",
        json={"tenant_id": "killbill-prod", "service": "proration-engine", "sha": "9f82d1a"},
    ).json()
    assert rem_resp["status"] == "remediated"

    # Re-running triage on TICKET-4902 after hotfix now reports WORKING_AS_PER_PRD!
    post_fix = client.post(
        "/api/triage",
        json={
            "tenant_id": "killbill-prod",
            "service": "billing-edge-api",
            "ticket_id": "TICKET-4902",
            "depth": 4,
            "bypass_memory": True,
        },
    ).json()
    assert post_fix["verdict"] == "WORKING_AS_PER_PRD"


def test_natural_language_ask_and_compare_depth_and_finding_dedup() -> None:
    # 1. Compare Depth=1 vs Depth=4 endpoint
    cmp_resp = client.post(
        "/api/compare-depth",
        json={"tenant_id": "killbill-prod", "service": "billing-edge-api", "ticket_id": "TICKET-4902"},
    ).json()
    assert cmp_resp["shallow_depth_1"]["verdict"] == "WORKING_AS_PER_PRD"
    assert cmp_resp["deep_depth_4"]["verdict"] == "PATCH_REGRESSION"

    # 2. Natural Language Ask endpoint (/api/ask)
    ask_discount = client.post(
        "/api/ask",
        json={"question": "Why did Globex lose their 15% discount with 42 seats?", "tenant_id": "killbill-prod"},
    ).json()
    assert ask_discount["verdict"] == "WORKING_AS_PER_PRD"
    assert ask_discount["citations"]["requirement_id"] == "PRD-DISC-209"

    ask_unknown = client.post(
        "/api/ask",
        json={"question": "What breaks if quantum-ledger-v9 fails?", "tenant_id": "killbill-prod"},
    ).json()
    assert ask_unknown["outcome"] == "unknown_service"

    # 3. Verify (:Finding) deduplication across repeated runs of the same ticket
    for _ in range(3):
        client.post(
            "/api/triage",
            json={
                "tenant_id": "killbill-prod",
                "service": "billing-edge-api",
                "ticket_id": "TICKET-4902",
                "depth": 4,
                "bypass_memory": True,
            },
        )
    graph_after = client.get("/api/graph?tenant_id=killbill-prod").json()
    findings_for_4902 = [f for f in graph_after["findings"] if f.get("ticket_id") == "TICKET-4902"]
    assert len(findings_for_4902) == 1


def test_vector_rag_vs_falkordb_benchmark_and_live_fault_injection() -> None:
    # 1. Run 6-scenario enterprise benchmark comparing Vector-Only RAG vs RAG + FalkorDB
    bm = client.post("/api/benchmark", json={"tenant_id": "killbill-prod"}).json()
    assert bm["total_scenarios"] == 6
    assert bm["falkordb_graph_scorecard"]["accuracy_pct"] == 100.0
    assert bm["falkordb_graph_scorecard"]["hallucination_rate_pct"] == 0.0
    assert bm["vector_rag_scorecard"]["accuracy_pct"] < 50.0
    assert bm["vector_rag_scorecard"]["hallucination_rate_pct"] >= 50.0

    # 2. First remediate default proration-engine regression, then inject a live fault on tax-ledger-adapter
    client.post(
        "/api/remediate",
        json={"tenant_id": "killbill-prod", "service": "proration-engine", "sha": "9f82d1a"},
    )
    inj = client.post(
        "/api/inject-fault",
        json={
            "tenant_id": "killbill-prod",
            "service": "tax-ledger-adapter",
            "author": "@chaos-bot",
            "summary": "feat(tax): bypass regional VAT rounding cache",
        },
    ).json()
    assert inj["status"] == "fault_injected"
    assert inj["service"] == "tax-ledger-adapter"

    # 3. Triage from entrypoint billing-edge-api now dynamically discovers the new fault on tax-ledger-adapter!
    triage_after = client.post(
        "/api/triage",
        json={
            "tenant_id": "killbill-prod",
            "service": "billing-edge-api",
            "ticket_id": "TICKET-4902",
            "depth": 4,
            "bypass_memory": True,
        },
    ).json()
    assert triage_after["verdict"] == "PATCH_REGRESSION"
    assert triage_after["root_cause_service"] == "tax-ledger-adapter"
    assert triage_after["vector_rag_comparison"]["rag_status"] == "FAILED_MULTI_HOP"

    # Re-seed clean state after chaos test
    client.post("/api/seed", json={"tenant_id": "killbill-prod"})


