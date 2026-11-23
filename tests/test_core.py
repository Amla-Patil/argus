import pytest
from argus.scope_guard import ScopeGuard, ScopeViolation
from argus.discovery import fingerprint

def test_out_of_scope_host_blocked():
    with pytest.raises(ScopeViolation): ScopeGuard().authorize("http://example.com", "GET", "cross_agency_access")
def test_write_method_blocked():
    with pytest.raises(ScopeViolation): ScopeGuard().authorize("http://127.0.0.1", "DELETE", "cross_agency_access")
def test_unapproved_test_blocked():
    with pytest.raises(ScopeViolation): ScopeGuard().authorize("http://127.0.0.1", "GET", "other_test")
def test_budget():
    g = ScopeGuard(max_requests=2); g.authorize("http://127.0.0.1", "GET", "cross_agency_access")
    with pytest.raises(ScopeViolation): g.authorize("http://127.0.0.1", "GET", "cross_agency_access")
def test_fingerprint_changes():
    e = {"path": "/a", "method": "GET", "params": [], "auth_required": True}
    assert fingerprint(e) != fingerprint({**e, "auth_required": False})

# ---- LangGraph planner tests (fake LLM, no network to a provider) ----
import json
from argus.graph import build_graph
from argus.discovery import inventory

EPS = inventory({"paths": {
    "/api/bookings/{booking_id}": {"get": {"parameters": [
        {"name": "booking_id", "in": "path", "required": True},
        {"name": "authorization", "in": "header", "required": True}]}}}})
S0 = {"base_url": "http://127.0.0.1:1", "endpoints": EPS, "proposals": [], "approved": [], "findings": [], "audit": []}

def run_with(llm, base_url="http://127.0.0.1:1"):
    return build_graph(llm).invoke({**S0, "base_url": base_url})

def test_llm_cannot_inject_unapproved_test_or_unknown_endpoint():
    evil = json.dumps([
        {"endpoint": "/api/bookings/{booking_id}", "method": "GET", "test_id": "sql_injection", "risk": "SQLI"},
        {"endpoint": "/admin/delete", "method": "DELETE", "test_id": "cross_agency_access", "risk": "X"}])
    r = run_with(lambda p: evil)
    assert r["findings"] == []
    assert sum(a.get("decision") == "REJECTED" for a in r["audit"]) == 2

def test_out_of_scope_target_denied_by_guard_even_if_llm_proposes_valid_plan():
    ok = json.dumps([{"endpoint": "/api/bookings/{booking_id}", "method": "GET",
                      "test_id": "cross_agency_access", "risk": "BOLA", "reason": "r", "priority": "high"}])
    r = run_with(lambda p: ok, base_url="http://example.com")
    assert r["findings"] == [] and any(a.get("decision") == "DENIED" for a in r["audit"])

def test_garbage_llm_output_falls_back_to_rules():
    r = run_with(lambda p: "I refuse to answer", base_url="http://example.com")
    assert any(a.get("planner") == "rules" for a in r["audit"])
    assert len(r["proposals"]) == 3  # BOLA + headers + rate_limit

# ---- API tests ----
from fastapi.testclient import TestClient
from argus.api import app

def test_api_rejects_out_of_scope_scan():
    r = TestClient(app).post("/api/scans", json={"base_url": "http://example.com"})
    assert r.status_code == 400 and "Out of scope" in r.json()["detail"]

def test_api_serves_dashboard_and_empty_state():
    c = TestClient(app)
    assert "Argus" in c.get("/").text and c.get("/api/scans").status_code == 200

# ---- PDF report tests ----
from io import BytesIO
from pypdf import PdfReader
from argus.report import build_report

FIX = {"base_url": "http://127.0.0.1:8001", "scanned_at": "t", "endpoints": 1,
       "inventory": [{"method": "GET", "path": "/a/{id}", "auth_required": True, "fingerprint": "abc"}],
       "changes": {"new": ["GET /a/{id}"], "modified": [], "removed": []},
       "findings": [{"id": "FND-001", "title": "Broken Object Level Authorization", "category": "BOLA", "severity": "CRITICAL",
                     "status": "CONFIRMED", "endpoint": "/a/{id}", "method": "GET", "confidence": 0.99,
                     "evidence": {"attack_status": 200, "leaked_fields": ["a", "b"]}, "remediation": "Fix <ownership> & retest"}],
       "audit": [{"step": "analyze", "planner": "rules"}, {"step": "guard", "decision": "APPROVED"}]}

def test_pdf_report_contains_findings_and_escapes_markup():
    pdf = build_report(FIX, "t1")
    assert pdf.startswith(b"%PDF")
    text = " ".join(p.extract_text() for p in PdfReader(BytesIO(pdf)).pages)
    assert "CONFIRMED" in text and "FND-001" in text and "<ownership>" in text

def test_report_endpoint_404_for_unknown_scan():
    assert TestClient(app).get("/api/scans/nope/report.pdf").status_code == 404

# ---- Retest comparison tests ----
from argus.compare import compare
mk = lambda st: {"findings": [{"method": "GET", "endpoint": "/a/{id}", "status": st}]}

def test_compare_outcomes():
    out = lambda b, a: compare(mk(b), mk(a))[0]["outcome"]
    assert out("CONFIRMED", "PASSED") == "FIXED"
    assert out("CONFIRMED", "CONFIRMED") == "STILL_VULNERABLE"
    assert out("PASSED", "CONFIRMED") == "REGRESSION"
    assert out("PASSED", "PASSED") == "UNCHANGED"

def test_inconclusive_retest_is_never_reported_as_fixed():
    assert compare(mk("CONFIRMED"), mk("INCONCLUSIVE"))[0]["outcome"] == "UNVERIFIED"

def test_pdf_includes_retest_section():
    r = {**FIX, "previous": "p1", "comparison": compare(mk("CONFIRMED"), mk("PASSED"))}
    text = " ".join(p.extract_text() for p in PdfReader(BytesIO(build_report(r, "t2"))).pages)
    assert "Retest comparison" in text and "FIXED" in text


# ---- New checks, guard rules, ZAP adapter ----
import httpx
from argus import checks, planner
from argus.zap import ZapClient
EP = {"path": "/api/bookings", "method": "POST"}
FX = {"destination": "Paris", "expected_amount": 50000, "tampered_amount": 1}

def _post(code, js=None):
    return lambda *a, **k: httpx.Response(code, json=js)

def test_price_confirmed_passed_inconclusive(monkeypatch):
    for code, js, want in [(201, {"amount": 1}, "CONFIRMED"), (201, {"amount": 50000}, "PASSED"),
                           (403, None, "PASSED"), (422, None, "INCONCLUSIVE"), (500, None, "INCONCLUSIVE")]:
        monkeypatch.setattr(httpx, "post", _post(code, js))
        assert checks.price_integrity("http://x", EP, "t", FX)["status"] == want

def test_rate_limit_and_headers(monkeypatch):
    ep = {"path": "/a/{id}", "method": "GET"}
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(200, json={}))
    assert checks.rate_limit("http://x", ep, "t", "B1", n=5)["status"] == "CONFIRMED"
    codes = iter([200, 200, 429, 429, 429])
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(next(codes), json={}))
    assert checks.rate_limit("http://x", ep, "t", "B1", n=5)["status"] == "PASSED"
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(200, json={}))
    f = checks.security_headers("http://x", ep, "t", "B1")
    assert f["status"] == "CONFIRMED" and f["severity"] == "LOW" and len(f["evidence"]["missing"]) == 3
    good = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store"}
    monkeypatch.setattr(httpx, "get", lambda *a, **k: httpx.Response(200, json={}, headers=good))
    assert checks.security_headers("http://x", ep, "t", "B1")["status"] == "PASSED"

def test_guard_method_is_per_test():
    g = ScopeGuard()
    g.authorize("http://127.0.0.1", "POST", "price_integrity", cost=1)
    with pytest.raises(ScopeViolation): g.authorize("http://127.0.0.1", "POST", "rate_limit")
    with pytest.raises(ScopeViolation): g.authorize("http://127.0.0.1", "GET", "price_integrity")

def test_validate_rejects_test_that_does_not_apply_to_endpoint():
    bad = json.dumps([{"endpoint": "/api/bookings/{booking_id}", "method": "GET", "test_id": "price_integrity", "risk": "X"}])
    r = run_with(lambda p: bad, base_url="http://example.com")
    assert any(a.get("decision") == "REJECTED" for a in r["audit"]) and r["findings"] == []

def test_zap_adapter_maps_alerts_as_reported_not_confirmed():
    def handler(req):
        p = req.url.path
        if "recordsToScan" in p: return httpx.Response(200, json={"recordsToScan": "0"})
        if "alerts" in p:
            return httpx.Response(200, json={"alerts": [{"alert": "Missing Anti-clickjacking Header", "risk": "Medium", "confidence": "Medium",
                    "url": "http://127.0.0.1:8001/api/x", "method": "GET", "param": "", "cweid": "1021", "solution": "Add X-Frame-Options"}] * 2})
        return httpx.Response(200, json={"Result": "OK"})
    z = ZapClient("http://zap", transport=httpx.MockTransport(handler))
    out = z.scan("http://127.0.0.1:8001", ["http://127.0.0.1:8001/api/x"])
    assert len(out) == 1 and out[0]["status"] == "REPORTED" and out[0]["severity"] == "MEDIUM" and out[0]["endpoint"] == "/api/x"
