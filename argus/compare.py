"""Compare two scan results for the same target. Never reports FIXED unless the retest PASSED."""

def compare(prev: dict, new: dict) -> list:
    key_of = lambda f: f"{f['method']} {f['endpoint']} {f.get('category', '')}"
    before = {key_of(f): f["status"] for f in prev["findings"]}
    rows = []
    for f in new["findings"]:
        key, after = key_of(f), f["status"]
        b = before.get(key)
        if b is None:
            out = "NEW"
        elif b == "CONFIRMED":
            out = {"PASSED": "FIXED", "CONFIRMED": "STILL_VULNERABLE"}.get(after, "UNVERIFIED")
        elif after == "CONFIRMED":
            out = "REGRESSION"
        else:
            out = "UNCHANGED" if b == after else "CHANGED"
        rows.append({"category": f.get("category", ""), "endpoint": f["endpoint"], "method": f["method"], "before": b or "-", "after": after, "outcome": out})
    return rows
