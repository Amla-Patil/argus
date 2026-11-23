"""Intentionally vulnerable travel API. Bind to localhost only."""
import time
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="Argus Demo Travel API", version="1.0")
bookings = {
    "B001": {"booking_id": "B001", "agency_id": "AGENCY_A", "destination": "Paris", "amount": 50000},
    "B002": {"booking_id": "B002", "agency_id": "AGENCY_B", "destination": "London", "amount": 35000},
}
FIXED = False  # demo switch: simulates deploying the fix
tokens = {"token-agency-a": "AGENCY_A", "token-agency-b": "AGENCY_B", "token-loadtest": "AGENCY_LOAD"}
FARES = {"Paris": 50000, "London": 35000}
hits: dict = {}

def agency_of(token: str) -> str:
    a = tokens.get(token)
    if not a:
        raise HTTPException(401, "Invalid authentication")
    if FIXED:  # throttling exists only after the fix: 20 requests / 10s per token
        now = time.time()
        q = [x for x in hits.get(token, []) if now - x < 10]
        if len(q) >= 20:
            raise HTTPException(429, "Too Many Requests")
        hits[token] = q + [now]
    return a

@app.middleware("http")
async def hardening(request: Request, call_next):
    resp = await call_next(request)
    if FIXED:
        resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Cache-Control": "no-store"})
    return resp

class BookingIn(BaseModel):
    destination: str
    amount: Optional[int] = None

def _create(agency, body: BookingIn, trust_client: bool):
    fare = FARES.get(body.destination)
    if fare is None:
        raise HTTPException(400, "Unknown destination")
    amount = body.amount if (trust_client and body.amount is not None) else fare
    bid = f"B{len(bookings) + 1:03d}"
    bookings[bid] = {"booking_id": bid, "agency_id": agency, "destination": body.destination, "amount": amount}
    return bookings[bid]

@app.post("/api/bookings", status_code=201)  # VULNERABLE: trusts client-supplied amount (until fixed)
def create_booking(body: BookingIn, authorization: str = Header(...)):
    return _create(agency_of(authorization), body, trust_client=not FIXED)

@app.post("/api/secure/bookings", status_code=201)  # FIXED: price always from server-side fare table
def create_booking_secure(body: BookingIn, authorization: str = Header(...)):
    return _create(agency_of(authorization), body, trust_client=False)

@app.get("/api/bookings/{booking_id}")  # VULNERABLE: authn only, no ownership check
def get_booking(booking_id: str, authorization: str = Header(...)):
    agency = agency_of(authorization)
    b = bookings.get(booking_id)
    if not b:
        raise HTTPException(404, "Not found")
    if FIXED and b["agency_id"] != agency:  # fix is live only after /demo/fix
        raise HTTPException(403, "Forbidden")
    return b

@app.get("/api/secure/bookings/{booking_id}")  # FIXED: authn + ownership
def get_booking_secure(booking_id: str, authorization: str = Header(...)):
    agency = agency_of(authorization)
    b = bookings.get(booking_id)
    if not b or b["agency_id"] != agency:
        raise HTTPException(403, "Forbidden")
    return b

@app.get("/api/invoices/{booking_id}")  # flaky: proves INCONCLUSIVE handling
def invoice(booking_id: str, authorization: str = Header(...)):
    agency_of(authorization)
    raise HTTPException(500, "Invoice service unavailable")

@app.post("/demo/fix", include_in_schema=False)
def demo_fix():
    global FIXED
    FIXED = True
    return {"fixed": True}

@app.post("/demo/reset", include_in_schema=False)
def demo_reset():
    global FIXED
    FIXED = False
    return {"fixed": False}
