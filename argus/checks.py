import httpx

def cross_agency_access(base_url, ep, victim_token, attacker_token, victim_resource_id):
    """BOLA: attacker's token requests victim's resource.
    CONFIRMED only when a control request proves the resource exists and the attacker reads it."""
    url = base_url + ep["path"].split("{")[0] + victim_resource_id
    h = lambda t: {"Authorization": t}
    control = httpx.get(url, headers=h(victim_token), timeout=10)
    attack = httpx.get(url, headers=h(attacker_token), timeout=10)
    evidence = {"control_status": control.status_code, "attack_status": attack.status_code,
                "resource_id": victim_resource_id}
    if control.status_code != 200 or attack.status_code >= 500:
        status, conf = "INCONCLUSIVE", 0.3
    elif attack.status_code == 200 and attack.json().get("agency_id") == control.json().get("agency_id"):
        status, conf = "CONFIRMED", 0.99
        evidence["leaked_fields"] = sorted(attack.json().keys())  # field names only; values redacted
    elif attack.status_code in (401, 403, 404):
        status, conf = "PASSED", 0.95
    else:
        status, conf = "INCONCLUSIVE", 0.4
    remediation = {"CONFIRMED": "Enforce resource ownership (agency_id) checks on every object access.",
                   "PASSED": "None required."}.get(status, "Re-run; target did not respond conclusively.")
    return {"title": "Broken Object Level Authorization", "category": "BOLA",
            "severity": "CRITICAL" if status == "CONFIRMED" else "INFO",
            "status": status, "endpoint": ep["path"], "method": ep["method"],
            "confidence": conf, "evidence": evidence, "remediation": remediation}

RATE_BURST = 25

def _finding(title, cat, sev, status, conf, ep, evidence, remediation):
    return {"title": title, "category": cat, "severity": sev if status == "CONFIRMED" else "INFO", "status": status,
            "endpoint": ep["path"], "method": ep["method"], "confidence": conf, "evidence": evidence,
            "remediation": remediation if status == "CONFIRMED" else
            ("None required." if status == "PASSED" else "Re-run; target did not respond conclusively.")}

def price_integrity(base_url, ep, token, fx):
    """Send a tampered client-side amount; CONFIRMED only if the server charges it instead of the catalogue fare."""
    r = httpx.post(base_url + ep["path"], headers={"Authorization": token}, timeout=10,
                   json={"destination": fx["destination"], "amount": fx["tampered_amount"]})
    ev = {"sent_amount": fx["tampered_amount"], "expected_amount": fx["expected_amount"], "status": r.status_code}
    amt = None
    try:
        amt = r.json().get("amount")
    except Exception:
        pass
    ev["charged_amount"] = amt
    if r.status_code in (200, 201) and amt == fx["tampered_amount"]:
        st, c = "CONFIRMED", 0.97
    elif r.status_code in (200, 201) and amt == fx["expected_amount"]:
        st, c = "PASSED", 0.95
    elif r.status_code in (400, 403):
        st, c = "PASSED", 0.8
    else:  # 422/5xx/other: payload may simply not match the endpoint, so no verdict
        st, c = "INCONCLUSIVE", 0.3
    return _finding("Client-controlled booking price", "PRICE_TAMPERING", "HIGH", st, c, ep, ev,
                    "Compute prices server-side from the fare catalogue; ignore or reject client-supplied amounts.")

def security_headers(base_url, ep, token, resource_id):
    url = base_url + ep["path"].split("{")[0] + resource_id
    r = httpx.get(url, headers={"Authorization": token}, timeout=10)
    h = {k.lower(): v for k, v in r.headers.items()}
    missing = []
    if h.get("x-content-type-options", "").lower() != "nosniff": missing.append("X-Content-Type-Options")
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""): missing.append("X-Frame-Options / CSP frame-ancestors")
    if "no-store" not in h.get("cache-control", "").lower(): missing.append("Cache-Control: no-store")
    if url.startswith("https") and "strict-transport-security" not in h: missing.append("Strict-Transport-Security")
    st = "INCONCLUSIVE" if r.status_code >= 500 else "CONFIRMED" if missing else "PASSED"
    return _finding("Missing security headers", "SECURITY_HEADERS", "LOW", st, 0.9 if st != "INCONCLUSIVE" else 0.3, ep,
                    {"status": r.status_code, "missing": missing}, "Add the missing headers to all authenticated API responses.")

def rate_limit(base_url, ep, token, resource_id, n=RATE_BURST):
    """Short burst with a dedicated synthetic account. Absence of throttling in n requests is lower-confidence."""
    url = base_url + ep["path"].split("{")[0] + resource_id
    codes = [httpx.get(url, headers={"Authorization": token}, timeout=10).status_code for _ in range(n)]
    ev = {"requests": n, "throttled_429": codes.count(429), "server_errors": sum(c >= 500 for c in codes)}
    st, c = (("PASSED", 0.9) if 429 in codes else ("INCONCLUSIVE", 0.3) if ev["server_errors"] else ("CONFIRMED", 0.7))
    return _finding("No rate limiting observed", "RATE_LIMITING", "MEDIUM", st, c, ep, ev,
                    "Add per-account throttling (HTTP 429) on authenticated endpoints.")
