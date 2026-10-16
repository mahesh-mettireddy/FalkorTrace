# Why Vector RAG Fails Incident Triage—And How We Built a 5-Agent Company Brain on FalkorDB

*By Mahesh Babu Metti Reddy (`@maheshmettireddy`) — Team LeoForge (`YVSBFW`) | Built for WeMakeDevs x FalkorDB Graph Hacks 2026*

---

## The Incident That Breaks Every RAG Pipeline

Imagine it is 3:15 AM. An enterprise SaaS customer upgrades their subscription mid-month from Basic (`$30/mo`) to Enterprise (`$90/mo`) through your public `billing-edge-api`. Under your Product Requirements Document (`PRD-INV-104`), a Day-15 upgrade on a 30-day billing cycle must use the exact `30/360` day-count convention and charge **$30.00**. Instead, the customer is billed **$45.00**.

If you hand this ticket (`TICKET-4902`) to a standard vector RAG agent:
1. It embeds `"Mid-month Enterprise upgrade charged $45 instead of $30 on billing-edge-api"`.
2. It retrieves chunks mentioning `billing-edge-api` and `PRD-INV-104`.
3. It checks recent commits on `billing-edge-api` and its immediate neighbor `subscription-service`—both of which are 100% clean.
4. **It hallucinates a conclusion.**

Why? Because the actual root cause does not sit inside any single record—it sits in **how six records connect across four hops**:

```text
(TICKET-4902)-[:REPORTS_ON]->(billing-edge-api)
  -[:DEPENDS_ON]->(subscription-service)
  -[:DEPENDS_ON]->(invoice-orchestrator)
  -[:DEPENDS_ON]->(proration-engine)
  -[:IMPLEMENTED_BY]->(FixedAndRecurringInvoiceItemGenerator.java)
  <-[:MODIFIED]-(Patch-v4.12.2 / sha:9f82d1a)
```

Four hours earlier, commit `sha:9f82d1a` modified `FixedAndRecurringInvoiceItemGenerator.java` three hops downstream inside `proration-engine`, introducing an off-by-one inclusive day-count bug that violated `PRD-INV-104`.

To solve this deterministically, we built **FalkorTrace** on **FalkorDB**.

---

## Architectural Principle 1: Model the Questions, Never Let the LLM Write Cypher

Following Aayush Sharma's blueprint (*"How to Build an Agent That Reasons Over a Graph"*), our LLM never touches the Cypher query language. Giving an LLM a schema and asking it to write Cypher in production fails in three ways:
- It invents relationship directions or property names.
- It writes unbounded traversals.
- It cannot prove why an answer came out the way it did.

Instead, FalkorTrace exposes **9 human-authored, parameterized tools** over the **Model Context Protocol (MCP)**. Every read tool executes strictly via `graph.ro_query(cypher, params)` (`GRAPH.RO_QUERY`).

### The Entity Resolution Gate (`resolve_service`)
Before any multi-hop traversal runs, Agent 1 verifies that the service name actually exists in the tenant's FalkorDB graph:

```python
def resolve_service(graph, name: str):
    res = graph.ro_query(
        "MATCH (s:Service {name: $name}) RETURN s.name AS name, s.tier AS tier",
        {"name": name},
    )
    return res.result_set[0] if res.result_set else None
```

When a user asks FalkorTrace to triage `legacy-cobol-mainframe`, `resolve_service()` returns `None` in **0.2ms**, halts the swarm immediately (`0` downstream queries executed), and returns the deterministic `unknown_service` answer shape.

---

## Architectural Principle 2: Depth=1 vs. Depth=4 and GraphBLAS Speed

FalkorDB represents graphs internally as **sparse adjacency matrices** and compiles Cypher traversals into **GraphBLAS linear algebra** ($A \times B \times A^T$). That allows our variable-length blast radius and patch inspection tools to run on every step of our 5-agent loop in sub-millisecond latency:

```cypher
MATCH path = (s:Service {name: $service})-[:DEPENDS_ON*1..4]->(dep:Service)
WHERE length(path) <= $depth
RETURN DISTINCT dep.name AS dependency, dep.tier AS tier,
       length(path) AS hops, [n IN nodes(path) | n.name] AS via
ORDER BY hops ASC, dependency ASC
```

In our dashboard, dragging the **Blast Radius Depth Slider** from `depth=1` to `depth=4` on `TICKET-4902` demonstrates why graph databases exist in 5 seconds:
- At **`depth=1`**, only `subscription-service` is visible. All code modules are compliant.
- At **`depth=4`**, the traversal walks `billing-edge-api → subscription-service → invoice-orchestrator → proration-engine`, catches `sha:9f82d1a` on `FixedAndRecurringInvoiceItemGenerator.java`, proves it violates `PRD-INV-104`, and pages `@meera-nair` on `#oncall-core-billing`.

---

## Architectural Principle 3: Native Graph Algorithms as Agent Tools

Pattern matching is only half of incident triage. FalkorTrace wraps four native FalkorDB algorithm procedures (`CALL algo.<name>()`) directly as agent tools:

1. **Weighted Shortest Path (`CALL algo.SPpaths`):** Proves the exact lowest-weight dependency route between the reported entrypoint service and the downstream failing module.
2. **Load-Bearing Criticality (`CALL algo.pageRank`):** Ranks every microservice in the estate by structural dependency gravity so on-call engineers know whether a regression sits on a critical core engine.
3. **Architectural Island Detection (`CALL algo.WCC`):** Identifies Weakly Connected Components. When `audit-vault-archiver` is queried, `resolve_service` confirms the service exists, while `algo.WCC` proves it sits in an isolated component with zero dependency paths—returning the honest `not_in_the_graph` shape instead of falsely claiming "nothing is broken."
4. **Chokepoint Detection (`CALL algo.betweenness`):** Pinpoints bridge services that sit on the highest fraction of shortest paths across the architecture.

---

## Architectural Principle 4: Cross-Session Memory & Hardware Multigraph Isolation

In FalkorDB, **agent memory is just more nodes**. When our 5-agent swarm resolves an investigation, it writes a `(:Finding)` node back to the graph via `graph.query()`:

```cypher
MATCH (s:Service {name: $service})
CREATE (f:Finding {id: $id, verdict: $verdict, text: $text, at: $at, session: $session})
CREATE (f)-[:ABOUT]->(s)
```

On the next session, `recall_past_findings` checks `(:Finding)-[:ABOUT]->(:Service)` *before* running any multi-hop traversal, returning `answered_from_memory` in **~1ms** alongside the exact timestamp and session ID when the conclusion was learned.

Furthermore, instead of relying on error-prone `WHERE tenant_id = ...` clauses, every customer tenant gets its own isolated FalkorDB graph via one line of Python:

```python
graph = db.select_graph(f"falkortrace:{tenant_id}")
```

---

## Architectural Principle 5: The Post-Generation Hallucination Guardrail (`accepts()`)

Even when an LLM is only asked to summarize structured rows, it can still invent plausible service names like `auth-gateway`. Every summary in FalkorTrace passes through `accepts(sentence, answer)`:

```python
SERVICE_TOKEN_RE = re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+\b")

def accepts(sentence: str, answer: dict) -> tuple[bool, str]:
    known = set(answer["services"]) | {h for p in answer["paths"] for h in p} | set(answer["allowed_tokens"])
    invented = set(SERVICE_TOKEN_RE.findall(sentence.lower())) - known
    if invented:
        return False, f"named services not in the graph result: {sorted(invented)}"
    return True, "ok"
```

If any token is not backed by FalkorDB's result set, the output is rejected and replaced with a deterministic, citation-backed template.

---

## Try FalkorTrace Live

Check out the full source code, Cypher queries, and 1-command Docker setup in our repository!
