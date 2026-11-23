import hashlib, json, os
import httpx

def fetch_openapi(base_url):
    return httpx.get(f"{base_url}/openapi.json", timeout=10).json()

def inventory(spec):
    eps = []
    for path, ops in spec.get("paths", {}).items():
        for method, op in ops.items():
            params = [{"name": p["name"], "in": p["in"], "required": p.get("required", False)}
                      for p in op.get("parameters", [])]
            eps.append({"path": path, "method": method.upper(), "params": params,
                        "has_body": "requestBody" in op,
                        "auth_required": any(p["in"] == "header" and p["name"].lower() == "authorization"
                                             and p["required"] for p in params)})
    return eps

def fingerprint(ep):
    canon = json.dumps({**{k: ep[k] for k in ("path", "method", "params", "auth_required")}, "has_body": ep.get("has_body", False)}, sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]

def diff(eps, state_file):
    old = json.load(open(state_file)) if os.path.exists(state_file) else {}
    cur = {f"{e['method']} {e['path']}": fingerprint(e) for e in eps}
    res = {"new": [k for k in cur if k not in old],
           "modified": [k for k in cur if k in old and old[k] != cur[k]],
           "removed": [k for k in old if k not in cur]}
    json.dump(cur, open(state_file, "w"), indent=2)
    return res
