"""FastAPI scan API + static dashboard. Run: uvicorn argus.api:app --port 8000"""
import os, threading, time, uuid
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from .report import build_report
from .compare import compare
import httpx
from pydantic import BaseModel
from .scan import run
from .llm import gemini_llm
from .scope_guard import ScopeGuard, ScopeViolation

app = FastAPI(title="Argus API")
SCANS: dict = {}
LOCK = threading.Lock()
INDEX = Path(__file__).resolve().parent.parent / "frontend" / "index.html"
os.makedirs("reports", exist_ok=True)

class ScanReq(BaseModel):
    base_url: str = "http://127.0.0.1:8001"

def _job(sid, url):
    try:
        with LOCK:  # one scan at a time: shared inventory state file
            r = run(url, out=f"reports/{sid}.json", llm=gemini_llm())
        prev = SCANS.get(SCANS[sid].get("previous") or "", {}).get("result")
        if prev:
            r["comparison"], r["previous"] = compare(prev, r), SCANS[sid]["previous"]
        SCANS[sid].update(status="done", result=r)
    except Exception as e:
        SCANS[sid].update(status="failed", error=f"{type(e).__name__}: {e}")

def _summary(s):
    f = (s.get("result") or {}).get("findings", [])
    cnt = lambda st: sum(x["status"] == st for x in f)
    return {"id": s["id"], "base_url": s["base_url"], "status": s["status"], "started": s["started"],
            "error": s.get("error"), "previous": s.get("previous"), "confirmed": cnt("CONFIRMED"), "passed": cnt("PASSED"),
            "inconclusive": cnt("INCONCLUSIVE")}

def _start(url, previous=None):
    try:
        ScopeGuard().check_host(url)
    except ScopeViolation as e:
        raise HTTPException(400, f"Out of scope: {e}")
    sid = uuid.uuid4().hex[:8]
    SCANS[sid] = {"id": sid, "base_url": url, "status": "running", "started": time.strftime("%H:%M:%S"), "previous": previous}
    threading.Thread(target=_job, args=(sid, url), daemon=True).start()
    return {"id": sid}

@app.post("/api/scans", status_code=202)
def start_scan(req: ScanReq):
    return _start(req.base_url)

@app.post("/api/scans/{sid}/retest", status_code=202)
def retest(sid: str):
    s = SCANS.get(sid)
    if not s:
        raise HTTPException(404, "Unknown scan")
    if s["status"] != "done":
        raise HTTPException(409, "Scan not finished")
    return _start(s["base_url"], previous=sid)

@app.post("/api/demo/{action}")
def demo_control(action: str, req: ScanReq):
    """Demo-only: flips the vulnerable demo target between vulnerable and fixed. Scope-checked."""
    if action not in ("fix", "reset"):
        raise HTTPException(404, "Unknown action")
    try:
        ScopeGuard().check_host(req.base_url)
    except ScopeViolation as e:
        raise HTTPException(400, f"Out of scope: {e}")
    return httpx.post(f"{req.base_url}/demo/{action}", timeout=10).json()

@app.get("/api/scans")
def list_scans():
    return [_summary(s) for s in reversed(list(SCANS.values()))]

@app.get("/api/scans/{sid}")
def get_scan(sid: str):
    if sid not in SCANS:
        raise HTTPException(404, "Unknown scan")
    return SCANS[sid]

@app.get("/api/scans/{sid}/report.pdf")
def scan_report(sid: str):
    s = SCANS.get(sid)
    if not s:
        raise HTTPException(404, "Unknown scan")
    if s["status"] != "done":
        raise HTTPException(409, "Scan not finished")
    return Response(build_report(s["result"], sid), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="argus-report-{sid}.pdf"'})

@app.get("/api/latest")
def latest():
    done = [s for s in SCANS.values() if s["status"] == "done"]
    return done[-1]["result"] if done else None

@app.get("/")
def dashboard():
    return FileResponse(INDEX)
