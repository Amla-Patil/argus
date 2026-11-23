"""Optional OWASP ZAP adapter (ZAP daemon REST API). Passive by default; active scan only if ZAP_ACTIVE=1.
ZAP alerts are tool-reported, not verified by Argus: status REPORTED, never CONFIRMED."""
import os, time
import httpx

RISK = {"High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO"}
CONF = {"High": 0.8, "Medium": 0.6, "Low": 0.4, "False Positive": 0.1}

class ZapClient:
    def __init__(self, base, apikey="", active=False, transport=None):
        self.c, self.key, self.active = httpx.Client(base_url=base, timeout=30, transport=transport), apikey, active

    @classmethod
    def from_env(cls):
        url = os.getenv("ZAP_URL")
        return cls(url, os.getenv("ZAP_API_KEY", ""), os.getenv("ZAP_ACTIVE") == "1") if url else None

    def _get(self, path, **p):
        r = self.c.get(path, params={**p, "apikey": self.key}); r.raise_for_status(); return r.json()

    def scan(self, base_url, urls, max_alerts=25):
        for u in urls:
            self._get("/JSON/core/action/accessUrl/", url=u, followRedirects="true")
        for _ in range(60):
            if int(self._get("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) == 0:
                break
            time.sleep(0.5)
        if self.active:
            sid = self._get("/JSON/ascan/action/scan/", url=base_url, recurse="true")["scan"]
            for _ in range(240):
                if int(self._get("/JSON/ascan/view/status/", scanId=sid)["status"]) >= 100:
                    break
                time.sleep(1)
        seen, out = set(), []
        for a in self._get("/JSON/core/view/alerts/", baseurl=base_url)["alerts"]:
            k = (a["alert"], a["url"])
            if k in seen:
                continue
            seen.add(k)
            out.append({"title": a["alert"], "category": "ZAP", "severity": RISK.get(a["risk"], "INFO"), "status": "REPORTED",
                        "endpoint": a["url"].replace(base_url, "") or "/", "method": a.get("method", "GET"),
                        "confidence": CONF.get(a.get("confidence"), 0.4),
                        "evidence": {"param": a.get("param", ""), "cwe": a.get("cweid", ""), "source": "OWASP ZAP"},
                        "remediation": a.get("solution") or "See ZAP alert details."})
        return out[:max_alerts]
