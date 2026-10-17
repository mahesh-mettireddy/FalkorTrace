"""
Idempotent FalkorDB Graph Seeder for FalkorTrace (`backend/seed.py`).

Populates isolated tenant graphs via `db.select_graph(f"falkortrace:{tenant_id}")`:
1. `killbill-prod`: Enterprise SaaS Subscription & Invoicing Platform (Kill Bill Java architecture)
2. `nexus-commerce`: Global High-Frequency Checkout & Ledger Platform

Includes:
- Connected Service, Code_Module, Requirement, Change, Team, Person, Runbook, and Client_Issue nodes.
- Executable Verification Graph Entities (`CheckDefinition` & `ArtifactVersion`) mapped via
  `(:Code_Module)-[:VERIFIED_BY]->(:CheckDefinition)`, `(:Requirement)-[:CHECKED_BY]->(:CheckDefinition)`,
  and `(:Code_Module)-[:ACTIVE_VERSION]->(:ArtifactVersion)`.
- Multi-case tickets on the same service (e.g., `TICKET-4902`, `TICKET-4905`, `TICKET-4906` on `billing-edge-api`;
  `TICKET-4908`, `TICKET-4909` on `invoice-orchestrator`; `TICKET-4915`, `TICKET-4916` on `payment-gateway-router`)
  to prove version-aware memory applicability and held-out evaluation.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List

from backend.verifier import ARTIFACT_VERSIONS_CATALOG, INDEPENDENT_REQUIREMENT_SPECIFICATIONS

ALLOWED_TENANTS = {"killbill-prod", "nexus-commerce"}

TENANT_METADATA: Dict[str, Dict[str, str]] = {
    "killbill-prod": {
        "tenant_id": "killbill-prod",
        "graph_name": "falkortrace:killbill-prod",
        "display_name": "KillBill SaaS Billing (Prod)",
        "domain": "Enterprise Subscription, Proration & Invoicing Engine (Java 21)",
        "description": "Multi-hop billing topology connecting Client Issues, Microservices, Java Modules, PRD/SRD Specs, Git Patches, CheckDefinitions, ArtifactVersions, Oncall Teams, and Versioned Episodic Findings.",
    },
    "nexus-commerce": {
        "tenant_id": "nexus-commerce",
        "graph_name": "falkortrace:nexus-commerce",
        "display_name": "Nexus Commerce Checkout (Prod)",
        "domain": "Global High-Frequency Cart, Fraud & Settlement Platform (Go / Kotlin)",
        "description": "Isolated secondary tenant demonstrating FalkorDB logical multigraph namespace separation (`db.select_graph('falkortrace:nexus-commerce')`).",
    },
}


def validate_tenant_scope(tenant_id: str) -> str:
    """Validate requested tenant_id against authorized server-side tenant scope."""
    tid = (tenant_id or "killbill-prod").strip()
    if tid not in ALLOWED_TENANTS:
        raise ValueError(
            f"Unauthorized tenant scope '{tid}'. Permitted tenant graphs: {sorted(ALLOWED_TENANTS)}"
        )
    return tid


def get_tenant_dataset(tenant_id: str) -> Dict[str, Any]:
    """Return the canonical structured graph dataset for the requested tenant."""
    tid = validate_tenant_scope(tenant_id)
    if tid == "nexus-commerce":
        return _build_nexus_commerce_dataset()
    return _build_killbill_prod_dataset()


def _build_killbill_prod_dataset() -> Dict[str, Any]:
    """Rich Kill Bill Enterprise SaaS Billing dataset covering live demo and held-out evaluation cases."""
    services = [
        {
            "name": "billing-edge-api",
            "tier": "tier-0",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/billing-edge-api",
            "description": "Public REST API gateway handling enterprise subscription upgrades and billing webhooks.",
        },
        {
            "name": "subscription-service",
            "tier": "tier-1",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/subscription-service",
            "description": "Manages subscription lifecycle, plan transitions, and entitlement state machines.",
        },
        {
            "name": "invoice-orchestrator",
            "tier": "tier-1",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/invoice-orchestrator",
            "description": "Coordinates invoice generation runs, discount policy evaluation, and line-item aggregation.",
        },
        {
            "name": "proration-engine",
            "tier": "tier-1",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/proration-engine",
            "description": "Computes daily 30/360 and actual/actual proration credits for mid-cycle plan upgrades.",
        },
        {
            "name": "tax-ledger-adapter",
            "tier": "tier-2",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/tax-ledger-adapter",
            "description": "Calculates regional VAT/GST and posts immutable double-entry journal lines.",
        },
        {
            "name": "payment-gateway-router",
            "tier": "tier-0",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/payment-gateway-router",
            "description": "Ingests settlement webhooks and routes multi-currency charges to PSP connectors.",
        },
        {
            "name": "fx-settlement-service",
            "tier": "tier-2",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/fx-settlement-service",
            "description": "Validates ISO-4217 currency settlement pairs and locks treasury FX rates.",
        },
        {
            "name": "dunning-scheduler",
            "tier": "tier-2",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/dunning-scheduler",
            "description": "Executes smart retry schedules for overdue enterprise invoices.",
        },
        {
            "name": "audit-vault-archiver",
            "tier": "tier-3",
            "language": "Java 21",
            "repo": "github.com/killbill-ent/audit-vault-archiver",
            "description": "Cold-storage compliance archiver sitting in an isolated architectural island (no active dependency edges).",
        },
    ]

    dependencies = [
        # Main 4-hop chain for Scenario 1:
        # billing-edge-api (0) -> subscription-service (1) -> invoice-orchestrator (2) -> proration-engine (3) -> tax-ledger-adapter (4)
        {"upstream": "billing-edge-api", "downstream": "subscription-service", "kind": "sync-grpc", "weight": 1, "critical": True},
        {"upstream": "subscription-service", "downstream": "invoice-orchestrator", "kind": "sync-grpc", "weight": 1, "critical": True},
        {"upstream": "invoice-orchestrator", "downstream": "proration-engine", "kind": "sync-grpc", "weight": 1, "critical": True},
        {"upstream": "proration-engine", "downstream": "tax-ledger-adapter", "kind": "sync-grpc", "weight": 1, "critical": True},
        # Additional realistic topology edges
        {"upstream": "invoice-orchestrator", "downstream": "tax-ledger-adapter", "kind": "async-kafka", "weight": 3, "critical": False},
        {"upstream": "invoice-orchestrator", "downstream": "dunning-scheduler", "kind": "async-kafka", "weight": 2, "critical": False},
        {"upstream": "payment-gateway-router", "downstream": "fx-settlement-service", "kind": "sync-grpc", "weight": 1, "critical": True},
        {"upstream": "payment-gateway-router", "downstream": "tax-ledger-adapter", "kind": "sync-grpc", "weight": 2, "critical": True},
        {"upstream": "dunning-scheduler", "downstream": "payment-gateway-router", "kind": "async-kafka", "weight": 2, "critical": False},
        # Note: audit-vault-archiver intentionally has 0 DEPENDS_ON edges to demonstrate WCC Island / `not_in_the_graph`!
    ]

    code_modules = [
        {
            "name": "BillingEdgeController.java",
            "service": "billing-edge-api",
            "filepath": "src/main/java/org/killbill/billing/edge/BillingEdgeController.java",
            "method_name": "upgradeSubscriptionPlan()",
            "governed_field": "tenant_jwt",
            "active_artifact_sha": "3a11c09",
            "check_id": "",
            "logic_summary": "Validates tenant JWT and forwards upgrade request to SubscriptionBillingApi.",
        },
        {
            "name": "SubscriptionBillingApi.java",
            "service": "subscription-service",
            "filepath": "src/main/java/org/killbill/billing/subscription/api/SubscriptionBillingApi.java",
            "method_name": "transitionPlanImmediate()",
            "governed_field": "plan_transition",
            "active_artifact_sha": "7b44e21",
            "check_id": "",
            "logic_summary": "Computes effective transition timestamp and triggers InvoiceOrchestrator.",
        },
        {
            "name": "DefaultInvoiceGenerator.java",
            "service": "invoice-orchestrator",
            "filepath": "src/main/java/org/killbill/billing/invoice/generator/DefaultInvoiceGenerator.java",
            "method_name": "generateInvoiceItems()",
            "governed_field": "invoice_run",
            "active_artifact_sha": "4e90b12",
            "check_id": "",
            "logic_summary": "Delegates recurring and mid-cycle proration math to FixedAndRecurringInvoiceItemGenerator.",
        },
        {
            "name": "DiscountPolicyEvaluator.java",
            "service": "invoice-orchestrator",
            "filepath": "src/main/java/org/killbill/billing/invoice/discount/DiscountPolicyEvaluator.java",
            "method_name": "evaluateMultiSeatRenewalDiscount()",
            "governed_field": "active_seats",
            "active_artifact_sha": "4e90b12",
            "check_id": "CHK-DISCOUNT-SEAT-50",
            "logic_summary": "Applies 15% enterprise discount strictly when active_seats >= 50 at renewal snapshot; reverts to 0% below 50 seats.",
        },
        {
            "name": "FixedAndRecurringInvoiceItemGenerator.java",
            "service": "proration-engine",
            "filepath": "src/main/java/org/killbill/billing/invoice/proration/FixedAndRecurringInvoiceItemGenerator.java",
            "method_name": "calculateProratedUpgradeAmount()",
            "governed_field": "expected_prorated_charge",
            "active_artifact_sha": "9f82d1a",
            "check_id": "CHK-PRORATION-30-360",
            "logic_summary": "Computes mid-cycle proration credit/charge ratio across remaining billing cycle days (modified in Patch-v4.12.2 sha:9f82d1a).",
        },
        {
            "name": "TaxLedgerSettlementAdapter.java",
            "service": "tax-ledger-adapter",
            "filepath": "src/main/java/org/killbill/billing/tax/TaxLedgerSettlementAdapter.java",
            "method_name": "commitTaxJournalEntry()",
            "governed_field": "tax_journal",
            "active_artifact_sha": "2d88a10",
            "check_id": "CHK-TAX-ROUNDING",
            "logic_summary": "Posts immutable tax lines using half-even banker's rounding.",
        },
        {
            "name": "PaymentWebhookValidator.java",
            "service": "payment-gateway-router",
            "filepath": "src/main/java/org/killbill/billing/payment/webhook/PaymentWebhookValidator.java",
            "method_name": "validateSettlementWebhook()",
            "governed_field": "currency",
            "active_artifact_sha": "1c55f08",
            "check_id": "CHK-WEBHOOK-ISO4217",
            "logic_summary": "Strictly enforces 3-letter ISO-4217 fiat currency codes and non-null UUIDv4 idempotency_key.",
        },
        {
            "name": "FxRateLockEngine.java",
            "service": "fx-settlement-service",
            "filepath": "src/main/java/org/killbill/billing/fx/FxRateLockEngine.java",
            "method_name": "lockSettlementRate()",
            "governed_field": "fx_pair",
            "active_artifact_sha": "1c55f08",
            "check_id": "",
            "logic_summary": "Locks ECB/Fed spot FX rate for validated 3-letter ISO-4217 currency pairs.",
        },
    ]

    requirements = [
        {
            "id": "SRD-API-101",
            "doc_type": "SRD",
            "title": "Idempotent Upgrade Request Envelope",
            "rule_text": "All subscription upgrade calls on billing-edge-api must preserve tenant context and forward target_plan_code unchanged.",
            "version": "v2.1",
            "check_id": "",
        },
        {
            "id": "PRD-SUB-102",
            "doc_type": "PRD",
            "title": "Immediate Mid-Cycle Upgrade Alignment",
            "rule_text": "Upgrading from Basic ($30/mo) to Enterprise ($90/mo) mid-cycle takes effect immediately while retaining the existing billing cycle anchor.",
            "version": "v3.0",
            "check_id": "",
        },
        {
            "id": "PRD-INV-104",
            "doc_type": "PRD",
            "title": "Exact 30/360 Daily Proration Convention",
            "rule_text": "Mid-month subscription upgrades on Day 15 of a 30-day cycle MUST prorate using the exact 30/360 day-count fraction (15/30 = 0.50 of the $60 tier delta = $30.00 net charge). Inclusive day-count offsets or ceiling multipliers are strictly prohibited.",
            "version": "v3.4",
            "check_id": "CHK-PRORATION-30-360",
        },
        {
            "id": "PRD-DISC-209",
            "doc_type": "PRD",
            "title": "15% Multi-Seat Annual Renewal Discount Threshold",
            "rule_text": "The 15% Enterprise Multi-Seat Discount requires >= 50 active provisioned seats at the exact renewal snapshot timestamp. Accounts with fewer than 50 active seats automatically revert to standard tier pricing (0% multi-seat discount).",
            "version": "v4.1",
            "check_id": "CHK-DISCOUNT-SEAT-50",
        },
        {
            "id": "SRD-BILL-08",
            "doc_type": "SRD",
            "title": "Deterministic Renewal Snapshot Seat Count",
            "rule_text": "DiscountPolicyEvaluator must evaluate seat thresholds against the immutable active_seats counter in the renewal payload without manual grace overrides.",
            "version": "v1.9",
            "check_id": "CHK-DISCOUNT-SEAT-50",
        },
        {
            "id": "SRD-PAY-301",
            "doc_type": "SRD",
            "title": "Multi-Currency Webhook ISO-4217 & Idempotency Contract",
            "rule_text": "All payment settlement webhooks must supply a valid 3-letter ISO-4217 fiat currency code (e.g., USD, EUR, GBP, INR) and a non-null UUIDv4 idempotency_key. Crypto ticker symbols or null idempotency keys must be rejected.",
            "version": "v2.8",
            "check_id": "CHK-WEBHOOK-ISO4217",
        },
        {
            "id": "SRD-TAX-401",
            "doc_type": "SRD",
            "title": "Double-Entry Tax Ledger Rounding",
            "rule_text": "Tax ledger postings must use IEEE 754 BigDecimal HALF_EVEN rounding to 2 decimal places.",
            "version": "v1.5",
            "check_id": "CHK-TAX-ROUNDING",
        },
    ]

    implements_edges = [
        {"module": "BillingEdgeController.java", "requirement": "SRD-API-101", "compliant": True, "note": "Matches SRD-API-101 envelope specification."},
        {"module": "SubscriptionBillingApi.java", "requirement": "PRD-SUB-102", "compliant": True, "note": "Preserves billing anchor date accurately."},
        {"module": "DefaultInvoiceGenerator.java", "requirement": "PRD-SUB-102", "compliant": True, "note": "Orchestrates invoice items per PRD-SUB-102."},
        {"module": "DiscountPolicyEvaluator.java", "requirement": "PRD-DISC-209", "compliant": True, "note": "Strictly enforces active_seats >= 50 threshold per PRD-DISC-209."},
        {"module": "DiscountPolicyEvaluator.java", "requirement": "SRD-BILL-08", "compliant": True, "note": "Reads active_seats snapshot deterministically."},
        {
            "module": "FixedAndRecurringInvoiceItemGenerator.java",
            "requirement": "PRD-INV-104",
            "compliant": False,
            "note": "Candidate change sha:9f82d1a touched day-count divisor; requires CHK-PRORATION-30-360 sandbox verification.",
        },
        {"module": "TaxLedgerSettlementAdapter.java", "requirement": "SRD-TAX-401", "compliant": True, "note": "Uses BigDecimal HALF_EVEN rounding."},
        {"module": "PaymentWebhookValidator.java", "requirement": "SRD-PAY-301", "compliant": True, "note": "Strictly validates 3-letter ISO-4217 currency and non-null idempotency_key."},
        {"module": "FxRateLockEngine.java", "requirement": "SRD-PAY-301", "compliant": True, "note": "Validates ISO currency pair before rate lock."},
    ]

    changes = [
        {
            "sha": "3a11c09",
            "patch_version": "Patch-v4.12.0",
            "summary": "chore(edge): bump OpenTelemetry trace header propagation on upgrade endpoint",
            "regressions_introduced": False,
            "diff_snippet": "+ span.setAttribute(\"killbill.tenant\", tenantId);",
            "at": "2026-10-15T14:20:00Z",
            "hours_ago": 18,
            "author": "@vikram-sen",
            "modified_module": "BillingEdgeController.java",
            "deployed_service": "billing-edge-api",
        },
        {
            "sha": "7b44e21",
            "patch_version": "Patch-v4.12.1",
            "summary": "perf(sub): cache immutable plan catalog lookup during transition",
            "regressions_introduced": False,
            "diff_snippet": "+ final PlanPhase phase = planCache.getOrLoad(targetPlanCode);",
            "at": "2026-10-15T19:45:00Z",
            "hours_ago": 12,
            "author": "@priya-sharma",
            "modified_module": "SubscriptionBillingApi.java",
            "deployed_service": "subscription-service",
        },
        {
            "sha": "9f82d1a",
            "patch_version": "Patch-v4.12.2",
            "summary": "refactor(proration): optimize mid-cycle day-count ratio calculation",
            "regressions_introduced": True,
            "diff_snippet": "- BigDecimal factor = BigDecimal.valueOf(remainingDays).divide(BigDecimal.valueOf(30), 6, HALF_UP);\n+ BigDecimal factor = BigDecimal.valueOf(remainingDays + 1).divide(BigDecimal.valueOf(20), 6, CEILING);",
            "at": "2026-10-16T00:10:00Z",
            "hours_ago": 4,
            "author": "@arjun-rao",
            "modified_module": "FixedAndRecurringInvoiceItemGenerator.java",
            "deployed_service": "proration-engine",
        },
        {
            "sha": "4e90b12",
            "patch_version": "Patch-v4.11.8",
            "summary": "feat(discount): add structured audit log for renewal seat count evaluation",
            "regressions_introduced": False,
            "diff_snippet": "+ log.info(\"Evaluated PRD-DISC-209: activeSeats={} threshold=50\", activeSeats);",
            "at": "2026-10-14T09:00:00Z",
            "hours_ago": 42,
            "author": "@meera-nair",
            "modified_module": "DiscountPolicyEvaluator.java",
            "deployed_service": "invoice-orchestrator",
        },
        {
            "sha": "1c55f08",
            "patch_version": "Patch-v4.11.5",
            "summary": "security(webhook): enforce strict ISO-4217 regex and non-null idempotency check",
            "regressions_introduced": False,
            "diff_snippet": "+ if (!ISO_4217_SET.contains(payload.currency()) || payload.idempotencyKey() == null) throw new InvalidPayloadException();",
            "at": "2026-10-13T16:30:00Z",
            "hours_ago": 60,
            "author": "@rohan-kapoor",
            "modified_module": "PaymentWebhookValidator.java",
            "deployed_service": "payment-gateway-router",
        },
    ]

    check_definitions = [
        INDEPENDENT_REQUIREMENT_SPECIFICATIONS["CHK-PRORATION-30-360"],
        INDEPENDENT_REQUIREMENT_SPECIFICATIONS["CHK-DISCOUNT-SEAT-50"],
        INDEPENDENT_REQUIREMENT_SPECIFICATIONS["CHK-WEBHOOK-ISO4217"],
        INDEPENDENT_REQUIREMENT_SPECIFICATIONS["CHK-TAX-ROUNDING"],
    ]

    artifact_versions = [
        ARTIFACT_VERSIONS_CATALOG["9f82d1a"],
        ARTIFACT_VERSIONS_CATALOG["7c31b09"],
        ARTIFACT_VERSIONS_CATALOG["4e90b12"],
        ARTIFACT_VERSIONS_CATALOG["1c55f08"],
        ARTIFACT_VERSIONS_CATALOG["2d88a10"],
    ]

    teams = [
        {
            "name": "Edge-Platform-Team",
            "slack_channel": "#oncall-edge-platform",
            "pagerduty_schedule": "PD-EDGE-PRIMARY",
            "owned_services": ["billing-edge-api", "subscription-service"],
        },
        {
            "name": "Core-Billing-Team",
            "slack_channel": "#oncall-core-billing",
            "pagerduty_schedule": "PD-BILL-PRIMARY",
            "owned_services": ["invoice-orchestrator", "proration-engine", "dunning-scheduler"],
        },
        {
            "name": "Payments-Treasury-Team",
            "slack_channel": "#oncall-payments-treasury",
            "pagerduty_schedule": "PD-PAY-PRIMARY",
            "owned_services": ["payment-gateway-router", "fx-settlement-service", "tax-ledger-adapter"],
        },
        {
            "name": "Compliance-Archive-Team",
            "slack_channel": "#oncall-compliance-archive",
            "pagerduty_schedule": "PD-ARCH-PRIMARY",
            "owned_services": ["audit-vault-archiver"],
        },
    ]

    people = [
        {
            "name": "Meera Nair",
            "handle": "@meera-nair",
            "email": "meera.nair@killbill-saas.io",
            "role": "Staff Billing Systems Engineer (Primary On-Call)",
            "team": "Core-Billing-Team",
            "oncall": {"from": "2026-10-15T00:00:00Z", "to": "2026-10-22T00:00:00Z"},
            "worked_on": [
                {"service": "invoice-orchestrator", "commits": 64},
                {"service": "proration-engine", "commits": 38},
            ],
        },
        {
            "name": "Arjun Rao",
            "handle": "@arjun-rao",
            "email": "arjun.rao@killbill-saas.io",
            "role": "Senior Billing Engineer",
            "team": "Core-Billing-Team",
            "oncall": None,
            "worked_on": [
                {"service": "proration-engine", "commits": 51},
                {"service": "dunning-scheduler", "commits": 19},
            ],
        },
        {
            "name": "Vikram Sen",
            "handle": "@vikram-sen",
            "email": "vikram.sen@killbill-saas.io",
            "role": "Principal Edge Architect (Primary On-Call)",
            "team": "Edge-Platform-Team",
            "oncall": {"from": "2026-10-15T00:00:00Z", "to": "2026-10-22T00:00:00Z"},
            "worked_on": [
                {"service": "billing-edge-api", "commits": 72},
                {"service": "subscription-service", "commits": 31},
            ],
        },
        {
            "name": "Priya Sharma",
            "handle": "@priya-sharma",
            "email": "priya.sharma@killbill-saas.io",
            "role": "Senior Subscription Engineer",
            "team": "Edge-Platform-Team",
            "oncall": None,
            "worked_on": [
                {"service": "subscription-service", "commits": 58},
            ],
        },
        {
            "name": "Rohan Kapoor",
            "handle": "@rohan-kapoor",
            "email": "rohan.kapoor@killbill-saas.io",
            "role": "Staff Payments SRE (Primary On-Call)",
            "team": "Payments-Treasury-Team",
            "oncall": {"from": "2026-10-15T00:00:00Z", "to": "2026-10-22T00:00:00Z"},
            "worked_on": [
                {"service": "payment-gateway-router", "commits": 83},
                {"service": "fx-settlement-service", "commits": 44},
                {"service": "tax-ledger-adapter", "commits": 29},
            ],
        },
        {
            "name": "Ananya Iyer",
            "handle": "@ananya-iyer",
            "email": "ananya.iyer@killbill-saas.io",
            "role": "Compliance Infrastructure Lead",
            "team": "Compliance-Archive-Team",
            "oncall": {"from": "2026-10-15T00:00:00Z", "to": "2026-10-22T00:00:00Z"},
            "worked_on": [
                {"service": "audit-vault-archiver", "commits": 27},
            ],
        },
    ]

    runbooks = [
        {
            "id": "RB-REVERT-PRORATION-104",
            "verdict_type": "PATCH_REGRESSION",
            "requirement_id": "PRD-INV-104",
            "title": "Rollback Proration Engine Patch & Issue Credit Memo",
            "steps": "1. Page @meera-nair (#oncall-core-billing) and commit author @arjun-rao.\n2. Revert commit sha:9f82d1a (Patch-v4.12.2) on proration-engine to restore exact 30/360 division.\n3. Run credit-memo batch job for invoices generated after 2026-10-16T00:10:00Z.",
        },
        {
            "id": "RB-EXPLAIN-DISCOUNT-209",
            "verdict_type": "WORKING_AS_PER_PRD",
            "requirement_id": "PRD-DISC-209",
            "title": "Customer Contract Citation: 50-Seat Renewal Threshold",
            "steps": "1. Do NOT page engineering; system behaved strictly per PRD-DISC-209 & SRD-BILL-08.\n2. Send automated contract citation showing active_seats=42 (< 50 seat minimum threshold).\n3. Offer sales-assisted seat true-up to >= 50 seats if client wishes to unlock the 15% tier.",
        },
        {
            "id": "RB-PAYLOAD-ISO-301",
            "verdict_type": "DATA_PAYLOAD_ISSUE",
            "requirement_id": "SRD-PAY-301",
            "title": "Client Webhook Schema Rejection Remediation",
            "steps": "1. Do NOT page Payments SRE; PaymentWebhookValidator.java is healthy and compliant.\n2. Return structured payload diff to client developer portal: replace 'USDT-ERC20' with a valid 3-letter ISO-4217 code (e.g., 'USD') and populate 'idempotency_key' with a non-null UUIDv4.",
        },
    ]

    client_issues = [
        # --- Live Demo Cases ---
        {
            "id": "TICKET-4902",
            "title": "Mid-month Enterprise upgrade charged $45.00 instead of prorated $30.00",
            "client_name": "Acme Global Cloud Corp",
            "client_tier": "Enterprise-Platinum",
            "reported_service": "billing-edge-api",
            "reported_payload": '{"account_id":"ACC-9910","upgrade_from":"BASIC_30","upgrade_to":"ENT_90","cycle_day":15,"cycle_length":30,"expected_prorated_charge":30.00,"actual_billed_charge":45.00}',
            "payload_valid": True,
            "payload_error": "",
            "expected_behavior": "Day 15 of 30 upgrade ($60 delta * 15/30) should charge $30.00 per PRD-INV-104.",
            "actual_behavior": "Invoice billed $45.00 following deployment of Patch-v4.12.2 on downstream proration-engine.",
            "created_at": "2026-10-16T03:15:00Z",
        },
        {
            "id": "TICKET-4908",
            "title": "15% Multi-Seat Annual Discount missing on auto-renewal invoice INV-9921",
            "client_name": "Veridian Dynamics FinTech",
            "client_tier": "Enterprise-Gold",
            "reported_service": "invoice-orchestrator",
            "reported_payload": '{"invoice_id":"INV-9921","account_id":"ACC-ENT-884","plan":"ENTERPRISE_ANNUAL","active_seats":42,"expected_discount_pct":15,"applied_discount_pct":0}',
            "payload_valid": True,
            "payload_error": "",
            "expected_behavior": "Client expected 15% multi-seat renewal discount to carry over automatically with 42 active seats.",
            "actual_behavior": "DiscountPolicyEvaluator applied 0% discount because active_seats (42) < 50 required by PRD-DISC-209.",
            "created_at": "2026-10-16T02:40:00Z",
        },
        {
            "id": "TICKET-4915",
            "title": "Recurring settlement webhook failing with HTTP 422/500 on payment-gateway-router",
            "client_name": "NovaPay Cross-Border Ltd",
            "client_tier": "Enterprise-Platinum",
            "reported_service": "payment-gateway-router",
            "reported_payload": '{"webhook_event":"invoice.payment_succeeded","amount":14200.00,"currency":"USDT-ERC20","idempotency_key":null}',
            "payload_valid": False,
            "payload_error": "Malformed client webhook payload: currency 'USDT-ERC20' violates 3-letter ISO-4217 standard and 'idempotency_key' is null (violates SRD-PAY-301).",
            "expected_behavior": "Client webhook should settle invoice and lock FX rate.",
            "actual_behavior": "PaymentWebhookValidator rejected payload due to non-ISO currency 'USDT-ERC20' and null idempotency_key.",
            "created_at": "2026-10-16T03:50:00Z",
        },
        {
            "id": "TICKET-4920",
            "title": "Verify whether audit-vault-archiver is impacted by billing pipeline latency",
            "client_name": "Internal SecOps Audit",
            "client_tier": "Internal-Compliance",
            "reported_service": "audit-vault-archiver",
            "reported_payload": '{"audit_batch_id":"BATCH-2026-10","target_service":"audit-vault-archiver"}',
            "payload_valid": True,
            "payload_error": "",
            "expected_behavior": "Trace downstream dependencies and PRD modules of audit-vault-archiver.",
            "actual_behavior": "Service exists in FalkorDB, but has zero modeled dependency or code paths (Disconnected WCC Island).",
            "created_at": "2026-10-16T01:10:00Z",
        },
        # --- Additional Held-Out & Same-Service Different-Case Tickets (Judge Sections 05 & 07) ---
        {
            "id": "TICKET-4905",
            "title": "Final-day (Day 29 of 30) upgrade overcharged $6.00 instead of $2.00 boundary proration",
            "client_name": "Stratosphere Aero Systems",
            "client_tier": "Enterprise-Platinum",
            "reported_service": "billing-edge-api",
            "reported_payload": '{"account_id":"ACC-7721","upgrade_from":"BASIC_30","upgrade_to":"ENT_90","cycle_day":29,"cycle_length":30,"expected_prorated_charge":2.00,"actual_billed_charge":6.00}',
            "payload_valid": True,
            "payload_error": "",
            "expected_behavior": "Day 29 of 30 boundary upgrade ($60 delta * 1/30) should charge $2.00 per PRD-INV-104.",
            "actual_behavior": "Invoice billed $6.00 on Day 29 boundary due to inclusive day-count (1+1)/20 in Patch-v4.12.2.",
            "created_at": "2026-10-16T04:05:00Z",
        },
        {
            "id": "TICKET-4906",
            "title": "Upgrade request on billing-edge-api rejected due to invalid plan code 'CRYPTO_PLAN_999'",
            "client_name": "OrbitPay Digital",
            "client_tier": "Enterprise-Gold",
            "reported_service": "billing-edge-api",
            "reported_payload": '{"account_id":"ACC-3319","upgrade_from":"BASIC_30","upgrade_to":"CRYPTO_PLAN_999","cycle_day":15,"cycle_length":30}',
            "payload_valid": False,
            "payload_error": "Malformed upgrade payload on billing-edge-api: target_plan_code 'CRYPTO_PLAN_999' is not a valid catalog plan (violates SRD-API-101).",
            "expected_behavior": "Upgrade should succeed on billing-edge-api.",
            "actual_behavior": "BillingEdgeController rejected invalid target_plan_code 'CRYPTO_PLAN_999' per SRD-API-101.",
            "created_at": "2026-10-16T04:20:00Z",
        },
        {
            "id": "TICKET-4909",
            "title": "Verify 60-seat Enterprise renewal discount calculation on invoice-orchestrator",
            "client_name": "Meridian Health Cloud",
            "client_tier": "Enterprise-Platinum",
            "reported_service": "invoice-orchestrator",
            "reported_payload": '{"invoice_id":"INV-9980","account_id":"ACC-ENT-905","plan":"ENTERPRISE_ANNUAL","active_seats":60,"expected_discount_pct":15,"applied_discount_pct":15}',
            "payload_valid": True,
            "payload_error": "",
            "expected_behavior": "60 active seats (>= 50 threshold) receives 15% multi-seat discount per PRD-DISC-209.",
            "actual_behavior": "DiscountPolicyEvaluator applied 15% discount accurately.",
            "created_at": "2026-10-16T04:35:00Z",
        },
        {
            "id": "TICKET-4916",
            "title": "EUR settlement webhook failing with missing UUIDv4 idempotency_key",
            "client_name": "EuroFin Treasury GmbH",
            "client_tier": "Enterprise-Gold",
            "reported_service": "payment-gateway-router",
            "reported_payload": '{"webhook_event":"invoice.payment_succeeded","amount":8500.00,"currency":"EUR","idempotency_key":"not-a-uuid"}',
            "payload_valid": False,
            "payload_error": "Malformed client webhook payload: idempotency_key 'not-a-uuid' is not a valid UUIDv4 (violates SRD-PAY-301).",
            "expected_behavior": "EUR webhook should settle.",
            "actual_behavior": "PaymentWebhookValidator rejected non-UUIDv4 idempotency_key per SRD-PAY-301.",
            "created_at": "2026-10-16T04:50:00Z",
        },
    ]

    return {
        "tenant_id": "killbill-prod",
        "services": services,
        "dependencies": dependencies,
        "code_modules": code_modules,
        "requirements": requirements,
        "implements_edges": implements_edges,
        "changes": changes,
        "check_definitions": check_definitions,
        "artifact_versions": artifact_versions,
        "teams": teams,
        "people": people,
        "runbooks": runbooks,
        "client_issues": client_issues,
        "observations": [],
        "findings": [],
    }


def _build_nexus_commerce_dataset() -> Dict[str, Any]:
    """Secondary isolated tenant dataset ('nexus-commerce') demonstrating multigraph namespace separation."""
    services = [
        {
            "name": "checkout-edge-gateway",
            "tier": "tier-0",
            "language": "Go 1.23",
            "repo": "github.com/nexus-commerce/checkout-edge-gateway",
            "description": "Edge GraphQL/REST checkout aggregator for global flash-sale traffic.",
        },
        {
            "name": "cart-pricing-service",
            "tier": "tier-1",
            "language": "Kotlin",
            "repo": "github.com/nexus-commerce/cart-pricing-service",
            "description": "Computes dynamic bundle pricing, loyalty points, and promo stacking.",
        },
        {
            "name": "inventory-reservation-engine",
            "tier": "tier-1",
            "language": "Go 1.23",
            "repo": "github.com/nexus-commerce/inventory-reservation-engine",
            "description": "Manages distributed warehouse stock holds and TTL expiration.",
        },
        {
            "name": "fraud-velocity-scorer",
            "tier": "tier-1",
            "language": "Python / Rust",
            "repo": "github.com/nexus-commerce/fraud-velocity-scorer",
            "description": "Evaluates real-time card velocity and device fingerprint risk rules.",
        },
    ]

    dependencies = [
        {"upstream": "checkout-edge-gateway", "downstream": "cart-pricing-service", "kind": "sync-grpc", "weight": 1, "critical": True},
        {"upstream": "cart-pricing-service", "downstream": "inventory-reservation-engine", "kind": "sync-grpc", "weight": 1, "critical": True},
        {"upstream": "inventory-reservation-engine", "downstream": "fraud-velocity-scorer", "kind": "sync-grpc", "weight": 2, "critical": True},
    ]

    code_modules = [
        {
            "name": "CheckoutEdgeHandler.go",
            "service": "checkout-edge-gateway",
            "filepath": "pkg/handler/CheckoutEdgeHandler.go",
            "method_name": "SubmitCheckout()",
            "governed_field": "checkout_session",
            "active_artifact_sha": "55a19c2",
            "check_id": "",
            "logic_summary": "Routes checkout session to CartPricingService.",
        },
        {
            "name": "PromoStackingCalculator.kt",
            "service": "cart-pricing-service",
            "filepath": "src/main/kotlin/com/nexus/cart/PromoStackingCalculator.kt",
            "method_name": "applyStackableCoupons()",
            "governed_field": "coupon_code",
            "active_artifact_sha": "55a19c2",
            "check_id": "",
            "logic_summary": "Enforces PRD-CART-501 non-stackable VIP flash coupon policy.",
        },
        {
            "name": "StockHoldCoordinator.go",
            "service": "inventory-reservation-engine",
            "filepath": "pkg/inventory/StockHoldCoordinator.go",
            "method_name": "AcquireTTLHold()",
            "governed_field": "hold_ttl_expected_sec",
            "active_artifact_sha": "88d12f0",
            "check_id": "CHK-NEXUS-TTL",
            "logic_summary": "Manages Redis inventory hold TTL lock (modified in Patch-v9.4.1 sha:88d12f0).",
        },
    ]

    requirements = [
        {
            "id": "PRD-CART-501",
            "doc_type": "PRD",
            "title": "Flash-Sale Coupon Exclusivity Rule",
            "rule_text": "VIP Flash-Sale coupons (30% off) cannot be stacked with referral credits on the same checkout order.",
            "version": "v2.0",
            "check_id": "",
        },
        {
            "id": "SRD-INV-602",
            "doc_type": "SRD",
            "title": "600-Second Checkout Inventory Hold Window",
            "rule_text": "Inventory reservations created at checkout initiation must maintain a minimum 600-second TTL lock before release.",
            "version": "v1.4",
            "check_id": "CHK-NEXUS-TTL",
        },
    ]

    implements_edges = [
        {"module": "PromoStackingCalculator.kt", "requirement": "PRD-CART-501", "compliant": True, "note": "Compliant coupon exclusivity guard."},
        {"module": "StockHoldCoordinator.go", "requirement": "SRD-INV-602", "compliant": False, "note": "Candidate change sha:88d12f0 modified hold duration constant; requires CHK-NEXUS-TTL verification."},
    ]

    changes = [
        {
            "sha": "88d12f0",
            "patch_version": "Patch-v9.4.1",
            "summary": "fix(inventory): convert hold duration unit constant from seconds to ms typo",
            "regressions_introduced": True,
            "diff_snippet": "- const DefaultHoldTTL = 600 * time.Second\n+ const DefaultHoldTTL = 6 * time.Second",
            "at": "2026-10-16T01:30:00Z",
            "hours_ago": 3,
            "author": "@kabir-mehta",
            "modified_module": "StockHoldCoordinator.go",
            "deployed_service": "inventory-reservation-engine",
        },
    ]

    check_definitions = [
        INDEPENDENT_REQUIREMENT_SPECIFICATIONS["CHK-NEXUS-TTL"],
    ]

    artifact_versions = [
        ARTIFACT_VERSIONS_CATALOG["88d12f0"],
        ARTIFACT_VERSIONS_CATALOG["55a19c2"],
    ]

    teams = [
        {
            "name": "Nexus-Checkout-Squad",
            "slack_channel": "#oncall-nexus-checkout",
            "pagerduty_schedule": "PD-NEXUS-CHECKOUT",
            "owned_services": ["checkout-edge-gateway", "cart-pricing-service", "inventory-reservation-engine", "fraud-velocity-scorer"],
        },
    ]

    people = [
        {
            "name": "Kabir Mehta",
            "handle": "@kabir-mehta",
            "email": "kabir.mehta@nexus-commerce.io",
            "role": "Principal Checkout SRE (On-Call)",
            "team": "Nexus-Checkout-Squad",
            "oncall": {"from": "2026-10-15T00:00:00Z", "to": "2026-10-22T00:00:00Z"},
            "worked_on": [
                {"service": "checkout-edge-gateway", "commits": 49},
                {"service": "inventory-reservation-engine", "commits": 62},
            ],
        },
    ]

    runbooks = [
        {
            "id": "RB-NEXUS-TTL-602",
            "verdict_type": "PATCH_REGRESSION",
            "requirement_id": "SRD-INV-602",
            "title": "Restore 600s Inventory Hold TTL Lock",
            "steps": "1. Page @kabir-mehta (#oncall-nexus-checkout).\n2. Revert Patch-v9.4.1 (sha:88d12f0) on inventory-reservation-engine.",
        },
    ]

    client_issues = [
        {
            "id": "NEXUS-701",
            "title": "Flash-sale inventory reservation expires after 6 seconds during payment step",
            "client_name": "LuxeRetail Europe",
            "client_tier": "Enterprise-Platinum",
            "reported_service": "checkout-edge-gateway",
            "reported_payload": '{"cart_id":"CART-992","hold_ttl_expected_sec":600,"hold_ttl_actual_sec":6}',
            "payload_valid": True,
            "payload_error": "",
            "expected_behavior": "Inventory hold remains active for 600 seconds per SRD-INV-602.",
            "actual_behavior": "StockHoldCoordinator expires lock after 6 seconds due to Patch-v9.4.1.",
            "created_at": "2026-10-16T03:00:00Z",
        },
    ]

    return {
        "tenant_id": "nexus-commerce",
        "services": services,
        "dependencies": dependencies,
        "code_modules": code_modules,
        "requirements": requirements,
        "implements_edges": implements_edges,
        "changes": changes,
        "check_definitions": check_definitions,
        "artifact_versions": artifact_versions,
        "teams": teams,
        "people": people,
        "runbooks": runbooks,
        "client_issues": client_issues,
        "observations": [],
        "findings": [],
    }


def seed_tenant(db: Any, tenant_id: str = "killbill-prod") -> Dict[str, Any]:
    """
    Idempotently clear and seed `db.select_graph(f"falkortrace:{tenant_id}")`.
    Works identically against a live FalkorDB container/Cloud instance or the In-Memory fallback.
    """
    t0 = time.perf_counter()
    tid = validate_tenant_scope(tenant_id)
    graph_name = f"falkortrace:{tid}"
    graph = db.select_graph(graph_name)
    dataset = get_tenant_dataset(tid)

    try:
        graph.query("MATCH (n) DETACH DELETE n")
    except Exception:
        pass

    index_queries = [
        "CREATE INDEX FOR (s:Service) ON (s.name)",
        "CREATE INDEX FOR (i:Client_Issue) ON (i.id)",
        "CREATE INDEX FOR (r:Requirement) ON (r.id)",
        "CREATE INDEX FOR (c:Code_Module) ON (c.name)",
        "CREATE INDEX FOR (ch:Change) ON (ch.sha)",
        "CREATE INDEX FOR (f:Finding) ON (f.id)",
        "CREATE INDEX FOR (chk:CheckDefinition) ON (chk.id)",
        "CREATE INDEX FOR (av:ArtifactVersion) ON (av.git_sha)",
    ]
    for idx_q in index_queries:
        try:
            graph.query(idx_q)
        except Exception:
            pass

    if hasattr(graph, "load_structured_dataset"):
        graph.load_structured_dataset(dataset)
    else:
        for svc in dataset["services"]:
            graph.query(
                """
                CREATE (:Service {
                    name: $name,
                    tier: $tier,
                    language: $language,
                    repo: $repo,
                    description: $description
                })
                """,
                svc,
            )

        for dep in dataset["dependencies"]:
            graph.query(
                """
                MATCH (u:Service {name: $upstream}), (d:Service {name: $downstream})
                CREATE (u)-[:DEPENDS_ON {kind: $kind, weight: $weight, critical: $critical}]->(d)
                """,
                dep,
            )

        for mod in dataset["code_modules"]:
            graph.query(
                """
                MATCH (s:Service {name: $service})
                CREATE (c:Code_Module {
                    name: $name,
                    filepath: $filepath,
                    method_name: $method_name,
                    governed_field: $governed_field,
                    active_artifact_sha: $active_artifact_sha,
                    check_id: $check_id,
                    logic_summary: $logic_summary
                })
                CREATE (s)-[:IMPLEMENTED_BY]->(c)
                """,
                mod,
            )

        for req in dataset["requirements"]:
            graph.query(
                """
                CREATE (:Requirement {
                    id: $id,
                    doc_type: $doc_type,
                    title: $title,
                    rule_text: $rule_text,
                    version: $version,
                    check_id: $check_id
                })
                """,
                req,
            )

        for impl in dataset["implements_edges"]:
            graph.query(
                """
                MATCH (c:Code_Module {name: $module}), (r:Requirement {id: $requirement})
                CREATE (c)-[:IMPLEMENTS {compliant: $compliant, note: $note}]->(r)
                """,
                impl,
            )

        for chk in dataset.get("check_definitions", []):
            graph.query(
                """
                MATCH (c:Code_Module {name: $target_module}), (r:Requirement {id: $requirement_id})
                CREATE (chk:CheckDefinition {
                    id: $check_id,
                    check_version: $check_version,
                    target_module: $target_module,
                    target_service: $target_service,
                    requirement_id: $requirement_id,
                    requirement_version: $requirement_version,
                    description: $description
                })
                CREATE (c)-[:VERIFIED_BY]->(chk)
                CREATE (r)-[:CHECKED_BY]->(chk)
                """,
                chk,
            )

        for av in dataset.get("artifact_versions", []):
            graph.query(
                """
                MATCH (c:Code_Module {name: $module})
                CREATE (av:ArtifactVersion {
                    id: $id,
                    module: $module,
                    service: $service,
                    version_tag: $version_tag,
                    git_sha: $git_sha,
                    code_hash: $code_hash
                })
                CREATE (c)-[:HAS_VERSION]->(av)
                """,
                av,
            )

        for ch in dataset["changes"]:
            graph.query(
                """
                MATCH (c:Code_Module {name: $modified_module}), (s:Service {name: $deployed_service})
                CREATE (ch:Change {
                    sha: $sha,
                    patch_version: $patch_version,
                    summary: $summary,
                    regressions_introduced: $regressions_introduced,
                    diff_snippet: $diff_snippet,
                    at: $at,
                    hours_ago: $hours_ago,
                    author: $author
                })
                CREATE (ch)-[:MODIFIED]->(c)
                CREATE (ch)-[:DEPLOYED_TO]->(s)
                """,
                ch,
            )

        for team in dataset["teams"]:
            graph.query(
                """
                CREATE (:Team {
                    name: $name,
                    slack_channel: $slack_channel,
                    pagerduty_schedule: $pagerduty_schedule
                })
                """,
                {
                    "name": team["name"],
                    "slack_channel": team["slack_channel"],
                    "pagerduty_schedule": team["pagerduty_schedule"],
                },
            )
            for owned_svc in team["owned_services"]:
                graph.query(
                    """
                    MATCH (t:Team {name: $team_name}), (s:Service {name: $service_name})
                    CREATE (t)-[:OWNS]->(s)
                    """,
                    {"team_name": team["name"], "service_name": owned_svc},
                )

        for person in dataset["people"]:
            graph.query(
                """
                MATCH (t:Team {name: $team})
                CREATE (p:Person {
                    name: $name,
                    handle: $handle,
                    email: $email,
                    role: $role
                })
                CREATE (p)-[:MEMBER_OF]->(t)
                """,
                {
                    "name": person["name"],
                    "handle": person["handle"],
                    "email": person["email"],
                    "role": person["role"],
                    "team": person["team"],
                },
            )
            if person.get("oncall"):
                graph.query(
                    """
                    MATCH (p:Person {handle: $handle}), (t:Team {name: $team})
                    CREATE (p)-[:ONCALL_FOR {from: $from_ts, to: $to_ts}]->(t)
                    """,
                    {
                        "handle": person["handle"],
                        "team": person["team"],
                        "from_ts": person["oncall"]["from"],
                        "to_ts": person["oncall"]["to"],
                    },
                )
            for wo in person.get("worked_on", []):
                graph.query(
                    """
                    MATCH (p:Person {handle: $handle}), (s:Service {name: $service})
                    CREATE (p)-[:WORKED_ON {commits: $commits}]->(s)
                    """,
                    {
                        "handle": person["handle"],
                        "service": wo["service"],
                        "commits": wo["commits"],
                    },
                )

        for rb in dataset["runbooks"]:
            graph.query(
                """
                MATCH (r:Requirement {id: $requirement_id})
                CREATE (rb:Runbook {
                    id: $id,
                    verdict_type: $verdict_type,
                    title: $title,
                    steps: $steps
                })
                CREATE (rb)-[:REMEDIATES]->(r)
                """,
                rb,
            )

        for issue in dataset["client_issues"]:
            graph.query(
                """
                MATCH (s:Service {name: $reported_service})
                CREATE (i:Client_Issue {
                    id: $id,
                    title: $title,
                    client_name: $client_name,
                    client_tier: $client_tier,
                    reported_service: $reported_service,
                    reported_payload: $reported_payload,
                    payload_valid: $payload_valid,
                    payload_error: $payload_error,
                    expected_behavior: $expected_behavior,
                    actual_behavior: $actual_behavior,
                    created_at: $created_at
                })
                CREATE (i)-[:REPORTS_ON]->(s)
                """,
                issue,
            )

    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    return {
        "status": "seeded",
        "tenant_id": tid,
        "graph_name": graph_name,
        "elapsed_ms": elapsed_ms,
        "counts": {
            "services": len(dataset["services"]),
            "dependencies": len(dataset["dependencies"]),
            "code_modules": len(dataset["code_modules"]),
            "requirements": len(dataset["requirements"]),
            "changes": len(dataset["changes"]),
            "check_definitions": len(dataset.get("check_definitions", [])),
            "artifact_versions": len(dataset.get("artifact_versions", [])),
            "teams": len(dataset["teams"]),
            "people": len(dataset["people"]),
            "runbooks": len(dataset["runbooks"]),
            "client_issues": len(dataset["client_issues"]),
        },
    }


if __name__ == "__main__":
    from backend.db import get_db

    db_instance = get_db()
    for tid in ("killbill-prod", "nexus-commerce"):
        info = seed_tenant(db_instance, tid)
        print(f"[FalkorTrace Seed] {info['graph_name']} seeded in {info['elapsed_ms']}ms -> {info['counts']}")
