"""Usage: python -m argus.scan --base-url http://127.0.0.1:8001"""
import argparse, json, time
from . import discovery
from .graph import build_graph
from .llm import gemini_llm
from .scope_guard import ScopeGuard
from .zap import ZapClient


def run(base_url, state_file="reports/inventory.json", out="reports/findings.json", llm=None):
    ScopeGuard().check_host(base_url)  # scope check BEFORE any request is sent
    eps = discovery.inventory(discovery.fetch_openapi(base_url))
    changes = discovery.diff(eps, state_file)
    final = build_graph(llm, zap=ZapClient.from_env()).invoke({"base_url": base_url, "endpoints": eps, "proposals": [],
                                     "approved": [], "findings": [], "audit": []})
    result = {"scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"), "base_url": base_url, "endpoints": len(eps),
              "inventory": [{"method": e["method"], "path": e["path"], "auth_required": e["auth_required"],
                             "fingerprint": discovery.fingerprint(e)} for e in eps],
              "changes": changes, "findings": final["findings"], "audit": final["audit"]}
    json.dump(result, open(out, "w"), indent=2)
    return result

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--base-url", default="http://127.0.0.1:8001")
    r = run(ap.parse_args().base_url, llm=gemini_llm())
    print(f"Endpoints: {r['endpoints']} | new: {len(r['changes']['new'])} | modified: {len(r['changes']['modified'])}")
    print("Planner:", next((a["planner"] for a in r["audit"] if a.get("step") == "analyze"), "?"))
    for f in r["findings"]:
        print(f"[{f['status']:<12}] {f['severity']:<8} {f['method']} {f['endpoint']}  evidence={f['evidence']}")
