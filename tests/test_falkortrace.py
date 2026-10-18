"""
End-to-End Pytest Verification Suite for FalkorTrace (`tests/test_falkortrace.py`).

Verifies:
1. Scenario 1 (`TICKET-4902`): Depth=1 misses regression (`WORKING_AS_PER_PRD` with shallow warning) vs Depth=4 catches 3-hop `PATCH_REGRESSION` on `proration-engine` (`FixedAndRecurringInvoiceItemGenerator.java`, `sha:9f82d1a`, `PRD-INV-104`) by executing `CHK-PRORATION-30-360` and observing `$45.00` vs expected `$30.00`.
2. Executable Fixture Acceptance Test: Switching active artifact on `proration-engine` from `9f82d1a` (`v4.12.2-faulty`) to `7c31b09` (`v4.12.1-clean`) changes observed sandbox output from `$45.00` (`FAIL`) to `$30.00` (`PASS`) and flips verdict from `PATCH_REGRESSION` to `WORKING_AS_PER_PRD`.
3. Version-Aware Investigation Memory & Applicability Fingerprint Gate:
   - Exact fingerprint match (`TICKET-4902` repeat query) reuses verified observation (`REUSE_APPLICABLE_OBSERVATION`, `answered_from_memory`).
   - Same service, different input (`TICKET-4905` Day 29 boundary or `TICKET-4906` invalid plan code on `billing-edge-api`) refuses blind diagnosis reuse (`HYPOTHESIS_ONLY_DIFFERENT_INPUT`) and runs fresh sandbox verification.
   - Selective invalidation on remediation: `/api/remediate` marks prior `9f82d1a` findings as `STALE_VERSION_MISMATCH` (preserving audit history in FalkorDB rather than deleting them) and forces fresh verification (`INVALIDATED_STALE_VERSION`).
4. Scenario 2 (`TICKET-4908`): `WORKING_AS_PER_PRD` on `invoice-orchestrator` (`DiscountPolicyEvaluator.java`, `PRD-DISC-209`, 42 < 50 seats via `CHK-DISCOUNT-SEAT-50`).
5. Scenario 3 (`TICKET-4915`): `DATA_PAYLOAD_ISSUE` on `payment-gateway-router` (`PaymentWebhookValidator.java`, `SRD-PAY-301`, `USDT-ERC20` via `CHK-WEBHOOK-ISO4217`).
6. Scenario 4A (`legacy-cobol-mainframe`): `unknown_service` blocked at `resolve_service` gate with 1 tool call and 0 rows.
7. Scenario 4B (`audit-vault-archiver`): `not_in_the_graph` detected via WCC island analysis.
8. Multigraph Tenant Isolation (`falkortrace:killbill-prod` vs `falkortrace:nexus-commerce`) & tenant allowlist validation.
9. Post-Generation Entity-Reference Guardrail (`accepts()`) rejecting invented service/module identifiers.
10. 12-Case 4-System Benchmark (`/api/benchmark`) & Live Chaos Fault Injection (`/api/inject-fault`).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.agent import accepts, run_multi_agent_triage
from backend.db import GraphOperationError, InMemoryGraph, get_db
from backend.main import app
from backend.seed import get_tenant_dataset, seed_tenant, validate_tenant_scope
from backend.tools import (
    apply_hotfix_remediation,
    evaluate_memory_applicability,
    inject_live_fault,
    recall_all_tenant_findings,
    record_finding,
    resolve_service,
    run_approved_check,
)
from backend.verifier import compute_input_fingerprint, execute_sandboxed_Verification_check

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

    # 2. At depth=4, traverses 3 hops to proration-engine, selects CHK-PRORATION-30-360,
    # executes sandbox check against sha:9f82d1a, observes $45.00 vs expected $30.00 -> PATCH_REGRESSION
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
    assert res_d4["verification"]["check_id"] == "CHK-PRORATION-30-360"
    assert res_d4["verification"]["status"] == "FAIL"
    assert res_d4["verification"]["expected_value"] == "$30.00"
    assert res_d4["verification"]["observed_value"] == "$45.00"
    assert res_d4["guardrail"]["passed"] is True

    # 3. Subsequent call with exact same fingerprint and bypass_memory=False returns answered_from_memory!
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
    assert res_mem["applicability"]["decision"] == "REUSE_APPLICABLE_OBSERVATION"


def test_executable_fixture_acceptance_and_version_aware_memory_safety() -> None:
    # 1. Direct sandboxed check test: 9f82d1a fails ($45.00 vs $30.00), 7c31b09 passes ($30.00 vs $30.00)
    obs_faulty = execute_sandboxed_Verification_check(
        check_id="CHK-PRORATION-30-360",
        case_id="TICKET-4902",
        artifact_sha="9f82d1a",
        raw_payload='{"upgrade_from": "BASIC_30", "upgrade_to": "ENT_90", "cycle_day": 15, "cycle_length": 30}',
    )
    assert obs_faulty["status"] == "FAIL"
    assert obs_faulty["expected_value"] == "$30.00"
    assert obs_faulty["observed_value"] == "$45.00"

    obs_clean = execute_sandboxed_Verification_check(
        check_id="CHK-PRORATION-30-360",
        case_id="TICKET-4902",
        artifact_sha="7c31b09",
        raw_payload='{"upgrade_from": "BASIC_30", "upgrade_to": "ENT_90", "cycle_day": 15, "cycle_length": 30}',
    )
    assert obs_clean["status"] == "PASS"
    assert obs_clean["expected_value"] == "$30.00"
    assert obs_clean["observed_value"] == "$30.00"

    # 2. Record a finding on TICKET-4902 (billing-edge-api, Day 15 upgrade)
    first_run = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        depth=4,
        bypass_memory=True,
    )
    assert first_run["verdict"] == "PATCH_REGRESSION"

    # 3. Query a DIFFERENT ticket on the SAME service (TICKET-4905: Day 29 upgrade on billing-edge-api)
    # with bypass_memory=False. Must NOT blindly reuse TICKET-4902's conclusion!
    diff_case_run = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4905",
        depth=4,
        bypass_memory=False,
    )
    assert diff_case_run["outcome"] == "answered_with_path"
    assert diff_case_run["applicability"]["decision"] == "HYPOTHESIS_ONLY_DIFFERENT_INPUT"
    assert diff_case_run["verification"]["expected_value"] == "$2.00"
    assert diff_case_run["verification"]["observed_value"] == "$6.00"
    assert diff_case_run["verdict"] == "PATCH_REGRESSION"

    # 4. Query TICKET-4906 (invalid plan code on billing-edge-api) with bypass_memory=False.
    # Its direct contract has no mapped executable check, so triage must abstain rather than
    # run a fabricated fallback check from another service.
    payload_case_run = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4906",
        depth=4,
        bypass_memory=False,
    )
    assert payload_case_run["outcome"] == "insufficient_evidence"
    assert payload_case_run["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert payload_case_run["verification"] is None

    # 5. Clear memory, re-record TICKET-4902 (sha:9f82d1a), and simulate artifact rollback (/api/remediate) -> switches to 7c31b09
    client.post("/api/memory/clear", json={"tenant_id": "killbill-prod"})
    run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        depth=4,
        bypass_memory=True,
    )
    rem_resp = client.post(
        "/api/remediate",
        json={"tenant_id": "killbill-prod", "service": "proration-engine", "sha": "9f82d1a"},
    ).json()
    assert rem_resp["status"] == "remediated"
    assert rem_resp["activated_artifact_sha"] == "7c31b09"
    assert rem_resp["verification_observation"]["status"] == "PASS"

    # Verify historical findings were preserved as STALE_VERSION_MISMATCH (not deleted!)
    graph_snap = client.get("/api/graph?tenant_id=killbill-prod").json()
    stale_findings = [
        f for f in graph_snap["findings"]
        if f.get("ticket_id") == "TICKET-4902" and f.get("validity_state") == "STALE_VERSION_MISMATCH"
    ]
    assert len(stale_findings) >= 1

    # 6. Query TICKET-4902 again with bypass_memory=False: stale finding is rejected and fresh verification reports WORKING_AS_PER_PRD!
    post_rollback = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        depth=4,
        bypass_memory=False,
    )
    assert post_rollback["outcome"] == "answered_with_path"
    assert post_rollback["applicability"]["decision"] == "INVALIDATED_STALE_VERSION"
    assert post_rollback["verdict"] == "WORKING_AS_PER_PRD"
    assert post_rollback["verification"]["status"] == "PASS"


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
    assert res["verification"]["check_id"] == "CHK-DISCOUNT-SEAT-50"
    assert res["verification"]["status"] == "PASS"
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
    assert res["verification"]["check_id"] == "CHK-WEBHOOK-ISO4217"
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
    # Verify invalid tenant_id is rejected by tenant allowlist
    with pytest.raises(ValueError):
        validate_tenant_scope("unauthorized-tenant-999")

    # Verify nexus-commerce cannot resolve killbill-prod services
    res_cross = run_multi_agent_triage(
        tenant_id="nexus-commerce",
        service="billing-edge-api",
        depth=4,
        bypass_memory=True,
    )
    assert res_cross["outcome"] == "unknown_service"

    # Verify nexus-commerce resolves its own regression via CHK-NEXUS-TTL
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
    assert res_nexus["verification"]["check_id"] == "CHK-NEXUS-TTL"
    assert res_nexus["verification"]["status"] == "FAIL"

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
    assert health["mcp_tools_count"] == 12
    assert health["falkordb"]["engine_mode"] in ("LIVE_FALKORDB", "IN_MEMORY_FALLBACK")

    graph_resp = client.get("/api/graph?tenant_id=killbill-prod").json()
    assert len(graph_resp["nodes"]) > 25
    assert len(graph_resp["edges"]) > 25

    # Apply live simulated rollback on proration-engine sha:9f82d1a
    rem_resp = client.post(
        "/api/remediate",
        json={"tenant_id": "killbill-prod", "service": "proration-engine", "sha": "9f82d1a"},
    ).json()
    assert rem_resp["status"] == "remediated"

    # Re-running triage on TICKET-4902 after rollback now reports WORKING_AS_PER_PRD!
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

    # 3. Verify (:Finding) deduplication across repeated runs of the same fingerprint
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
    findings_for_4902 = [
        f for f in graph_after["findings"]
        if f.get("ticket_id") == "TICKET-4902" and f.get("validity_state") == "VALID"
    ]
    assert len(findings_for_4902) == 1


def test_four_system_12_case_benchmark_and_live_fault_injection() -> None:
    # 1. Run 12-scenario 4-System Benchmark
    bm = client.post("/api/benchmark", json={"tenant_id": "killbill-prod"}).json()
    assert bm["total_scenarios"] == 12
    assert bm["falkordb_graph_scorecard"]["accuracy_pct"] == 100.0
    assert bm["falkordb_graph_scorecard"]["hallucination_rate_pct"] == 0.0
    assert bm["vector_rag_scorecard"]["accuracy_pct"] < 50.0
    sys4 = bm["four_system_comparison"]
    assert sys4["system_a_lexical_tfidf"]["accuracy_pct"] == 33.3
    assert sys4["system_b_local_verifier_no_graph"]["accuracy_pct"] == 33.3
    assert sys4["system_c_falkordb_verifier_stateless"]["accuracy_pct"] == 100.0
    assert sys4["system_d_falkordb_verifier_memory"]["accuracy_pct"] == 100.0

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
    assert inj["requirement_violated"] == "SRD-TAX-401"

    # 3. Triage from entrypoint billing-edge-api now dynamically discovers & verifies the new fault on tax-ledger-adapter!
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
    assert triage_after["verification"]["check_id"] == "CHK-TAX-ROUNDING"
    assert triage_after["verification"]["status"] == "FAIL"
    assert triage_after["vector_rag_comparison"]["rag_status"] in ("FAILED_MULTI_HOP", "MISSED_MULTI_HOP_CANDIDATE")

    # Re-seed clean state after chaos test
    client.post("/api/seed", json={"tenant_id": "killbill-prod"})


def test_admin_token_guard_and_secret_redaction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FALKORTRACE_ADMIN_TOKEN", "test-admin-token")

    denied = client.post("/api/memory/clear", json={"tenant_id": "killbill-prod"})
    assert denied.status_code == 401

    allowed = client.post(
        "/api/memory/clear",
        json={"tenant_id": "killbill-prod"},
        headers={"X-FalkorTrace-Admin-Token": "test-admin-token"},
    )
    assert allowed.status_code == 200

    secret = "sk-test-secret-that-must-not-leak"
    llm = client.post(
        "/api/config/llm",
        json={"provider": "openai", "api_key": secret, "model": "test-model"},
        headers={"Authorization": "Bearer test-admin-token"},
    )
    assert llm.status_code == 200
    assert secret not in llm.text
    assert "key_preview" not in llm.json()["llm"]

    # Do not leave a test key in process-local runtime state for later tests.
    client.post(
        "/api/config/llm",
        json={"provider": "auto", "api_key": "", "model": ""},
        headers={"X-FalkorTrace-Admin-Token": "test-admin-token"},
    )


def test_production_admin_routes_fail_closed_without_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FALKORTRACE_ADMIN_TOKEN", raising=False)
    monkeypatch.setenv("VERCEL_ENV", "production")
    denied = client.post("/api/memory/clear", json={"tenant_id": "killbill-prod"})
    assert denied.status_code == 503
    assert "token" not in denied.text.lower()


def test_observation_and_finding_provenance_and_edges() -> None:
    graph = InMemoryGraph("falkortrace:killbill-prod")
    graph.load_structured_dataset(get_tenant_dataset("killbill-prod"))
    input_fp = compute_input_fingerprint(
        "killbill-prod",
        "billing-edge-api",
        "TICKET-4902",
        '{"upgrade_from":"BASIC_30","upgrade_to":"ENT_90","cycle_day":15,"cycle_length":30}',
    )
    observation, _ = run_approved_check(
        graph=graph,
        check_id="CHK-PRORATION-30-360",
        case_id="TICKET-4902",
        artifact_sha="9f82d1a",
        raw_payload='{"upgrade_from":"BASIC_30","upgrade_to":"ENT_90","cycle_day":15,"cycle_length":30}',
        tenant_id="killbill-prod",
        service="billing-edge-api",
        input_fingerprint=input_fp,
    )
    finding, _ = record_finding(
        graph=graph,
        service="billing-edge-api",
        verdict="PATCH_REGRESSION",
        text="verified regression",
        session="SES-PROVENANCE",
        root_cause_node="proration-engine",
        ticket_id="TICKET-4902",
        input_fingerprint=input_fp,
        artifact_sha="9f82d1a",
        req_version="v3.4",
        check_version="chk-v2.1",
        observation_id=observation["observation_id"],
        run_id=observation["run_id"],
        tenant_id="killbill-prod",
        requirement_id="PRD-INV-104",
        check_id="CHK-PRORATION-30-360",
    )

    stored_observation = graph._dataset["observations"][-1]
    stored_finding = graph._dataset["findings"][-1]
    assert stored_observation["tenant_id"] == "killbill-prod"
    assert stored_observation["service"] == "billing-edge-api"
    assert stored_observation["input_fingerprint"] == input_fp
    assert stored_observation["requirement_id"] == "PRD-INV-104"
    assert stored_observation["requirement_version"] == "v3.4"
    assert stored_finding["tenant_id"] == "killbill-prod"
    assert stored_finding["requirement_id"] == "PRD-INV-104"
    assert stored_finding["check_id"] == "CHK-PRORATION-30-360"
    assert finding["observation_id"] == observation["observation_id"]


def test_memory_applicability_rejects_requirement_or_check_identity_changes() -> None:
    finding = {
        "id": "FIND-IDENTITY",
        "service": "billing-edge-api",
        "root_cause_node": "proration-engine",
        "ticket_id": "TICKET-4902",
        "input_fingerprint": "fp:same",
        "artifact_sha": "9f82d1a",
        "requirement_id": "PRD-INV-104",
        "req_version": "v3.4",
        "check_id": "CHK-PRORATION-30-360",
        "check_version": "chk-v2.1",
        "validity_state": "VALID",
        "observation_id": "OBS-1",
    }
    current = {
        "proration-engine": {
            "requirement_id": "PRD-INV-104",
            "requirement_version": "v3.4",
            "check_id": "CHK-PRORATION-30-360",
            "check_version": "chk-v2.1",
        }
    }
    applicable = evaluate_memory_applicability(
        [finding],
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        input_fingerprint="fp:same",
        active_artifact_map={"proration-engine": "9f82d1a"},
        current_context_map=current,
    )
    assert applicable["decision"] == "REUSE_APPLICABLE_OBSERVATION"

    current["proration-engine"]["check_version"] = "chk-v3.0"
    rejected = evaluate_memory_applicability(
        [finding],
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        input_fingerprint="fp:same",
        active_artifact_map={"proration-engine": "9f82d1a"},
        current_context_map=current,
    )
    assert rejected["decision"] == "INVALIDATED_STALE_VERSION"
    assert rejected["can_reuse"] is False


def test_graph_errors_are_not_returned_as_empty_evidence() -> None:
    class BrokenGraph:
        def ro_query(self, *_args: object, **_kwargs: object) -> None:
            raise RuntimeError("backend unavailable")

    broken = BrokenGraph()
    with pytest.raises(GraphOperationError):
        resolve_service(broken, "billing-edge-api")
    with pytest.raises(GraphOperationError):
        recall_all_tenant_findings(broken)


def test_integrity_rejects_unknown_mutation_and_check_inputs() -> None:
    graph = InMemoryGraph("falkortrace:killbill-prod")
    graph.load_structured_dataset(get_tenant_dataset("killbill-prod"))

    with pytest.raises(ValueError, match="Unknown service"):
        apply_hotfix_remediation(graph, service="not-a-service", sha="9f82d1a")
    with pytest.raises(ValueError, match="Unknown change"):
        apply_hotfix_remediation(graph, service="proration-engine", sha="not-a-change")
    with pytest.raises(ValueError, match="Unknown service"):
        inject_live_fault(graph, service="not-a-service")
    with pytest.raises(ValueError, match="not available"):
        run_approved_check(
            graph,
            check_id="CHK-PRORATION-30-360",
            case_id="TICKET-4902",
            artifact_sha="not-an-artifact",
        )
    with pytest.raises(ValueError, match="Unknown ticket"):
        run_approved_check(
            graph,
            check_id="CHK-PRORATION-30-360",
            case_id="TICKET-9999",
            artifact_sha="9f82d1a",
            service="billing-edge-api",
        )
    with pytest.raises(ValueError, match="Unknown service"):
        run_approved_check(
            graph,
            check_id="CHK-PRORATION-30-360",
            case_id="CASE-UNKNOWN-SERVICE",
            artifact_sha="9f82d1a",
            service="not-a-service",
        )


def test_dynamic_fault_injection_persists_artifact_version_and_links_it() -> None:
    graph = InMemoryGraph("falkortrace:killbill-prod")
    graph.load_structured_dataset(get_tenant_dataset("killbill-prod"))
    result = inject_live_fault(graph, service="tax-ledger-adapter", tenant_id="killbill-prod")

    artifact = next(
        item for item in graph._dataset["artifact_versions"] if item["git_sha"] == result["sha"]
    )
    assert artifact["module"] == "TaxLedgerSettlementAdapter.java"
    assert artifact["service"] == "tax-ledger-adapter"
    assert artifact["dynamic"] is True
    observation, _ = run_approved_check(
        graph,
        check_id="CHK-TAX-ROUNDING",
        case_id="DYNAMIC-FAULT",
        artifact_sha=result["sha"],
        raw_payload='{"subtotal":"100.05","tax_rate":"0.185"}',
        tenant_id="killbill-prod",
        service="tax-ledger-adapter",
    )
    assert observation["status"] == "FAIL"
    assert observation["artifact_sha"] == result["sha"]


def test_verifier_rejects_malformed_json_and_requires_uuidv4() -> None:
    malformed = execute_sandboxed_Verification_check(
        check_id="CHK-WEBHOOK-ISO4217",
        case_id="CASE-MALFORMED",
        artifact_sha="1c55f08",
        raw_payload='{"currency":"EUR"',
    )
    assert malformed["status"] == "ERROR"
    assert "Malformed JSON" in malformed["error"]

    uuid_v4 = execute_sandboxed_Verification_check(
        check_id="CHK-WEBHOOK-ISO4217",
        case_id="CASE-UUIDV4",
        artifact_sha="1c55f08",
        raw_payload='{"currency":"EUR","idempotency_key":"550e8400-e29b-41d4-a716-446655440000"}',
    )
    assert uuid_v4["status"] == "PASS"

    uuid_v1 = execute_sandboxed_Verification_check(
        check_id="CHK-WEBHOOK-ISO4217",
        case_id="CASE-UUIDV1",
        artifact_sha="1c55f08",
        raw_payload='{"currency":"EUR","idempotency_key":"550e8400-e29b-11d4-a716-446655440000"}',
    )
    assert uuid_v1["status"] == "INVALID_INPUT"
    assert uuid_v1["payload_schema_failed"] is True


def test_triage_rejects_unknown_or_cross_service_tickets() -> None:
    mismatch = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4908",
        depth=4,
        bypass_memory=True,
    )
    assert mismatch["outcome"] == "ticket_service_mismatch"
    assert mismatch["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert mismatch["verification"] is None

    missing = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-9999",
        depth=4,
        bypass_memory=True,
    )
    assert missing["outcome"] == "unknown_ticket"
    assert missing["verification"] is None


def test_triage_abstains_when_reachable_graph_has_no_verification_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from backend.db import InMemoryFalkorDB

    class TestFallbackDB(InMemoryFalkorDB):
        def status(self) -> dict[str, object]:
            return {"engine_mode": "IN_MEMORY_FALLBACK", "is_simulated_fallback": True}

    isolated_db = TestFallbackDB()
    seed_tenant(isolated_db, "killbill-prod")
    graph = isolated_db.select_graph("falkortrace:killbill-prod")
    graph._dataset["check_definitions"] = []
    for module in graph._dataset["code_modules"]:
        module["check_id"] = ""
    for requirement in graph._dataset["requirements"]:
        requirement["check_id"] = ""
    monkeypatch.setattr("backend.agent.get_db", lambda: isolated_db)

    result = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        depth=4,
        bypass_memory=True,
    )
    assert result["outcome"] == "insufficient_evidence"
    assert result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert result["verification"] is None
    assert result["citations"]["verification_available"] is False


def test_memory_clear_removes_findings_and_observations() -> None:
    run = run_multi_agent_triage(
        tenant_id="killbill-prod",
        service="billing-edge-api",
        ticket_id="TICKET-4902",
        depth=4,
        bypass_memory=True,
    )
    assert run["verification"] is not None
    before = client.get("/api/graph?tenant_id=killbill-prod").json()
    assert before["graph_source"] in ("IN_MEMORY_FIXTURE", "LIVE_FALKORDB_QUERY")
    assert before["findings"]
    assert before["observations"]

    cleared = client.post("/api/memory/clear", json={"tenant_id": "killbill-prod"})
    assert cleared.status_code == 200
    after = client.get("/api/graph?tenant_id=killbill-prod").json()
    assert after["findings"] == []
    assert after["observations"] == []
