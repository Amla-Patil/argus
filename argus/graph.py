"""LangGraph workflow: analyze -> validate -> guard -> execute -> zap.
The LLM proposes; validate + guard (deterministic) decide; execute runs fixed catalogue code."""
import json, re
from typing import TypedDict, Callable, Optional
from langgraph.graph import StateGraph, END
from . import planner, checks
from .fixtures import *
from .scope_guard import ScopeGuard, ScopeViolation

class State(TypedDict):
    base_url: str
    endpoints: list
    proposals: list
    approved: list
    findings: list
    audit: list

PROMPT = """You are a security test planner for an authorized staging API.
Choose tests ONLY from this catalogue (test_id: applicability):
{catalogue}

Endpoints (JSON):
{endpoints}

Return ONLY a JSON array. Each item: {{"endpoint": "<path>", "method": "<HTTP method>",
"risk": "<e.g. BOLA>", "test_id": "<catalogue id>", "reason": "<short>", "priority": "high|medium|low"}}.
Propose each test at most once per endpoint. Skip endpoints where no catalogue test applies."""

RUN = {"cross_agency_access": lambda u, ep: checks.cross_agency_access(u, ep, VICTIM_TOKEN, ATTACKER_TOKEN, VICTIM_RESOURCE),
       "security_headers": lambda u, ep: checks.security_headers(u, ep, VICTIM_TOKEN, VICTIM_RESOURCE),
       "rate_limit": lambda u, ep: checks.rate_limit(u, ep, RATE_TOKEN, VICTIM_RESOURCE),
       "price_integrity": lambda u, ep: checks.price_integrity(u, ep, VICTIM_TOKEN, PRICE_FIXTURE)}
COST = {"cross_agency_access": 2, "security_headers": 1, "rate_limit": checks.RATE_BURST, "price_integrity": 1}

def _extract_json(text: str):
    m = re.search(r"\[.*\]", text, re.S)
    return json.loads(m.group(0)) if m else json.loads(text)

def _rules(endpoints):
    return [{"endpoint": p["endpoint"]["path"], "method": p["endpoint"]["method"], "risk": p["risk"], "test_id": p["test_id"],
             "reason": p["reason"], "priority": p["priority"]} for p in planner.plan(endpoints)]

def build_graph(llm: Optional[Callable[[str], str]] = None, guard: Optional[ScopeGuard] = None, zap=None):
    guard = guard or ScopeGuard()

    def analyze(s: State):
        audit = list(s["audit"])
        if llm is None:
            audit.append({"step": "analyze", "planner": "rules", "note": "no LLM configured"}); props = _rules(s["endpoints"])
        else:
            slim = [{"path": e["path"], "method": e["method"], "auth_required": e["auth_required"], "has_body": e.get("has_body", False),
                     "params": [p["name"] for p in e["params"]]} for e in s["endpoints"]]
            try:
                props = _extract_json(llm(PROMPT.format(catalogue=json.dumps(planner.CATALOGUE, indent=1), endpoints=json.dumps(slim, indent=1))))
                audit.append({"step": "analyze", "planner": "llm", "proposed": len(props)})
            except Exception as e:  # unparsable / provider failure -> deterministic fallback
                audit.append({"step": "analyze", "planner": "rules", "note": f"LLM failed ({type(e).__name__}); fallback"}); props = _rules(s["endpoints"])
        return {"proposals": props, "audit": audit}

    def validate(s: State):
        """Reject unknown tests, unknown endpoints, tests that don't apply to the endpoint, and duplicates."""
        known = {(e["method"], e["path"]): e for e in s["endpoints"]}
        ok, audit, seen = [], list(s["audit"]), set()
        for p in s["proposals"]:
            ep = known.get((str(p.get("method", "")).upper(), p.get("endpoint")))
            tid = p.get("test_id")
            key = (tid, p.get("method"), p.get("endpoint"))
            if tid not in planner.CATALOGUE or ep is None or not planner.APPLIES[tid](ep) or key in seen:
                audit.append({"step": "validate", "decision": "REJECTED", "proposal": p}); continue
            seen.add(key); ok.append({**p, "ep": ep})
        return {"approved": ok, "audit": audit}

    def guard_node(s: State):
        ok, audit = [], list(s["audit"])
        for p in s["approved"]:
            try:
                guard.authorize(s["base_url"], p["method"], p["test_id"], cost=COST[p["test_id"]])
                audit.append({"step": "guard", "decision": "APPROVED", "endpoint": p["endpoint"], "test": p["test_id"]}); ok.append(p)
            except ScopeViolation as e:
                audit.append({"step": "guard", "decision": "DENIED", "endpoint": p["endpoint"], "test": p["test_id"], "why": str(e)})
        return {"approved": ok, "audit": audit}

    def execute(s: State):
        findings, audit = [], list(s["audit"])
        for p in s["approved"]:
            try:
                f = RUN[p["test_id"]](s["base_url"], p["ep"])
            except Exception as e:
                audit.append({"step": "execute", "test": p["test_id"], "endpoint": p["endpoint"], "error": type(e).__name__}); continue
            f["id"], f["planner_reason"] = f"FND-{len(findings)+1:03d}", p.get("reason", "")
            findings.append(f)
        return {"findings": findings, "audit": audit}

    def zap_node(s: State):
        if zap is None:
            return {}
        audit = list(s["audit"])
        try:
            guard.authorize(s["base_url"], "GET", "zap_passive", cost=len(s["endpoints"]))
            urls = [s["base_url"] + e["path"].replace(e["path"][e["path"].find("{"):], VICTIM_RESOURCE) if "{" in e["path"] else s["base_url"] + e["path"]
                    for e in s["endpoints"] if e["method"] == "GET"]
            zf = zap.scan(s["base_url"], urls)
            for f in zf:
                f["id"] = f"FND-{len(s['findings']) + 1 + zf.index(f):03d}"
            audit.append({"step": "zap", "decision": "APPROVED", "alerts": len(zf)})
            return {"findings": s["findings"] + zf, "audit": audit}
        except Exception as e:
            audit.append({"step": "zap", "error": f"{type(e).__name__}: {e}"}); return {"audit": audit}

    g = StateGraph(State)
    for name, fn in (("analyze", analyze), ("validate", validate), ("guard", guard_node), ("execute", execute), ("zap", zap_node)):
        g.add_node(name, fn)
    g.set_entry_point("analyze")
    for a, b in (("analyze", "validate"), ("validate", "guard"), ("guard", "execute"), ("execute", "zap"), ("zap", END)):
        g.add_edge(a, b)
    return g.compile()
