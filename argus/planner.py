"""Test catalogue, deterministic applicability rules, and a rules-based planner (LLM fallback).
APPLIES is enforced by the graph's validate step, so an LLM cannot aim a test at an unsuitable endpoint."""
_auth_get_1p = lambda e: e["method"] == "GET" and e["auth_required"] and e["path"].count("{") == 1
_price = lambda e: (e["method"] == "POST" and e["auth_required"] and e.get("has_body")
                    and "bookings" in e["path"] and "{" not in e["path"])
CATALOGUE = {
    "cross_agency_access": "GET endpoint with one path param and required auth (BOLA)",
    "price_integrity": "POST booking-creation endpoint with auth and a body (client-supplied price tampering)",
    "security_headers": "authenticated GET endpoint; checks response hardening headers (run once per target)",
    "rate_limit": "authenticated GET endpoint; short burst to detect missing throttling (run once per target)"}
APPLIES = {"cross_agency_access": _auth_get_1p, "price_integrity": _price,
           "security_headers": _auth_get_1p, "rate_limit": _auth_get_1p}
_META = {"cross_agency_access": ("BOLA", "Object ID in path; ownership must be enforced", "high"),
         "price_integrity": ("PRICE_TAMPERING", "Booking price must be computed server-side", "high"),
         "security_headers": ("SECURITY_HEADERS", "Authenticated responses should carry hardening headers", "low"),
         "rate_limit": ("RATE_LIMITING", "Authenticated endpoints should throttle bursts", "medium")}

def _mk(ep, tid):
    risk, reason, prio = _META[tid]
    return {"endpoint": ep, "test_id": tid, "risk": risk, "reason": reason, "priority": prio}

def plan(endpoints):
    plans = [_mk(e, t) for e in endpoints for t in ("cross_agency_access", "price_integrity") if APPLIES[t](e)]
    first = next((e for e in endpoints if APPLIES["security_headers"](e)), None)
    if first:
        plans += [_mk(first, "security_headers"), _mk(first, "rate_limit")]
    return plans
