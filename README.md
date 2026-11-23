# Argus

![tests](https://github.com/Amla-Patil/argus/actions/workflows/tests.yml/badge.svg)

Agentic security testing for travel-booking APIs. An AI planner proposes which tests to run. A deterministic guard decides what is actually allowed to execute.

> **Authorized targets only.** Argus is built for staging and demo systems you own or have permission to test. By default it will only talk to `127.0.0.1` and `localhost`.

## Why

Security testing an API by hand is slow, and letting an AI loose on a target is risky. Argus keeps the useful part of the AI (choosing what to test) and removes the risky part: the model can only pick from a fixed catalogue, and every request passes through a rule-based guard before it is sent.

## How it works

```
OpenAPI discovery -> fingerprint / change detection -> planner (catalogue only)
   -> ScopeGuard (deterministic) -> check runs -> findings.json + audit log -> PDF report
```

- **Planner:** a LangGraph flow (analyze, validate, guard, execute). With `GOOGLE_API_KEY` set it uses Gemini. Without it, a rules-based planner runs, so the tool works with no AI key.
- **ScopeGuard:** enforces allowed hosts, the HTTP method allowed for each test, and a request budget (150 per scan by default). Anything outside that raises a violation and is logged.
- **Retest:** compares a new scan with an earlier one and labels each finding `FIXED`, `STILL_VULNERABLE`, `REGRESSION` or `UNVERIFIED`. A finding is only `FIXED` when its check actually passes.

## Checks

| Check | What it looks for |
|---|---|
| `cross_agency_access` | One agency reading another agency's bookings (broken object-level authorization), using a control request |
| `price_integrity` | A booking accepted with a tampered price |
| `security_headers` | Missing security response headers |
| `rate_limit` | No throttling under a burst of 25 requests, using a dedicated synthetic account |

Each test has a deterministic rule for when it applies (`planner.APPLIES`) and an allowed method (`scope_guard.DEFAULT_TESTS`). Optional OWASP ZAP findings (`ZAP_URL`, `ZAP_API_KEY`, `ZAP_ACTIVE=1`) are labelled `REPORTED` and never `CONFIRMED`.

## Run it

```bash
pip install -r requirements.txt

# 1. start the deliberately vulnerable demo target (localhost only)
cd vulnerable-demo && uvicorn main:app --port 8001 &
cd ..

# 2a. run a scan from the command line
python -m argus.scan --base-url http://127.0.0.1:8001

# 2b. or start the API and dashboard
uvicorn argus.api:app --port 8000      # then open http://127.0.0.1:8000
```

The demo target has a switch to simulate a fix: `POST /demo/fix` hardens it (ownership check, server-side pricing, security headers, throttling) and `POST /demo/reset` undoes it. Scan, apply the fix, then retest to watch findings move to `FIXED`.

Reports: `GET /api/scans/{id}/report.pdf`, or the dashboard's Reports tab.

## Tests

```bash
pytest tests
```

20 tests cover the scope guard, planner, checks, retest comparison and reporting.

## Limitations

- Only tested against the bundled demo API, not a real system.
- Four checks, so this is not a full scanner and is no substitute for a professional penetration test.
- The dashboard is a single HTML file that loads React from a CDN, so it needs internet access.
- ZAP integration is optional and its results stay unverified.

## Next

More checks, authenticated scanning against real staging environments, and a second demo target to test generality.
