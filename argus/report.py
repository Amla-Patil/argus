"""PDF security report from a scan result dict (ReportLab)."""
from collections import Counter
from io import BytesIO
from xml.sax.saxutils import escape as esc
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

COL = {"CONFIRMED": "#c0392b", "CRITICAL": "#c0392b", "PASSED": "#1e8449", "INFO": "#1e8449",
       "INCONCLUSIVE": "#b9770e", "new": "#2471a3", "modified": "#b9770e", "FIXED": "#1e8449", "REGRESSION": "#c0392b", "STILL_VULNERABLE": "#c0392b", "UNVERIFIED": "#b9770e", "NEW": "#2471a3", "HIGH": "#c0392b", "MEDIUM": "#b9770e", "LOW": "#2471a3", "REPORTED": "#7d3c98"}
SS = getSampleStyleSheet()
SM = ParagraphStyle("sm", parent=SS["Normal"], fontSize=8.5, leading=11)
H1 = ParagraphStyle("h1", parent=SS["Heading1"], fontSize=15, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#0e1116"))
H2 = ParagraphStyle("h2", parent=SS["Heading2"], fontSize=11.5, spaceBefore=8, spaceAfter=4)
P = lambda t, s=SM: Paragraph(t, s)
tag = lambda t: f'<font color="{COL.get(t, "#333333")}"><b>{esc(str(t))}</b></font>'

def _table(rows, widths, header=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8cdd4")),
          ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        st += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5"))]
    t.setStyle(TableStyle(st)); return t

def _footer(c, d):
    c.saveState(); c.setFont("Helvetica", 8); c.setFillColor(colors.grey)
    c.drawString(18 * mm, 10 * mm, "Argus security report - authorized test environment only")
    c.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {d.page}"); c.restoreState()

def build_report(result: dict, scan_id: str = "-") -> bytes:
    f = result["findings"]; cnt = Counter(x["status"] for x in f)
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm, title=f"Argus report {scan_id}", author="Argus")
    W = A4[0] - 36 * mm
    s = [Paragraph("Argus Security Report", SS["Title"]),
         _table([[P("<b>Target</b>"), P(esc(result["base_url"]))], [P("<b>Scan ID</b>"), P(esc(scan_id))],
                 [P("<b>Scanned at</b>"), P(esc(result["scanned_at"]))],
                 [P("<b>Endpoints tested</b>"), P(str(result["endpoints"]))]], [35 * mm, W - 35 * mm], header=False),
         Paragraph("1. Executive summary", H1)]
    verdict = (f"{cnt['CONFIRMED']} confirmed vulnerabilit{'y' if cnt['CONFIRMED'] == 1 else 'ies'} require remediation."
               if cnt["CONFIRMED"] else "No vulnerabilities were confirmed in this scan.")
    s += [P(verdict + f" {cnt['PASSED']} test(s) passed and {cnt['INCONCLUSIVE']} were inconclusive "
            "(inconclusive results are not confirmed vulnerabilities and should be re-run)."
            + (f" {cnt['REPORTED']} item(s) reported by ZAP are unverified." if cnt["REPORTED"] else ""), SS["Normal"]), Spacer(1, 6),
          _table([[P("<b>Confirmed</b>"), P("<b>Passed</b>"), P("<b>Inconclusive</b>"), P("<b>New endpoints</b>"), P("<b>Modified</b>")],
                  [P(tag("CONFIRMED").replace("CONFIRMED", str(cnt["CONFIRMED"]))), P(str(cnt["PASSED"])), P(str(cnt["INCONCLUSIVE"])),
                   P(str(len(result["changes"]["new"]))), P(str(len(result["changes"]["modified"])))]], [W / 5] * 5),
          Paragraph("2. Findings", H1)]
    for x in f:
        kv = [[P("<b>Status</b>"), P(tag(x["status"]))], [P("<b>Severity</b>"), P(tag(x["severity"]))],
              [P("<b>Endpoint</b>"), P(esc(f"{x['method']} {x['endpoint']}"))],
              [P("<b>Confidence</b>"), P(f"{round(x['confidence'] * 100)}%")]]
        if x.get("planner_reason"):
            kv.append([P("<b>Planner reason</b>"), P(esc(x["planner_reason"]))])
        for k, v in x["evidence"].items():
            kv.append([P(f"<b>Evidence: {esc(k)}</b>"), P(esc(", ".join(v) if isinstance(v, list) else str(v)))])
        kv.append([P("<b>Remediation</b>"), P(esc(x["remediation"]))])
        s.append(KeepTogether([Paragraph(f"{esc(x['id'])} - {esc(x['title'])}", H2), _table(kv, [38 * mm, W - 38 * mm], header=False), Spacer(1, 6)]))
    s.append(Paragraph("3. API inventory", H1))
    ch = lambda k: "new" if k in result["changes"]["new"] else "modified" if k in result["changes"]["modified"] else "-"
    rows = [[P("<b>Method</b>"), P("<b>Path</b>"), P("<b>Auth</b>"), P("<b>Fingerprint</b>"), P("<b>Change</b>")]]
    for e in result["inventory"]:
        c = ch(f"{e['method']} {e['path']}")
        rows.append([P(e["method"]), P(esc(e["path"])), P("required" if e["auth_required"] else "none"), P(e["fingerprint"]), P(tag(c) if c != "-" else "-")])
    s.append(_table(rows, [18 * mm, W - 18 * mm - 78 * mm, 20 * mm, 30 * mm, 30 * mm]))
    n = 4
    if result.get("comparison"):
        s.append(Paragraph("4. Retest comparison", H1))
        s.append(P(f"Compared with previous scan {esc(result.get('previous', '-'))}. FIXED is reported only when the retest passed; "
                   "an inconclusive retest is UNVERIFIED.", SS["Normal"]))
        rows = [[P("<b>Endpoint</b>"), P("<b>Before</b>"), P("<b>After</b>"), P("<b>Outcome</b>")]]
        for c in result["comparison"]:
            rows.append([P(esc(f"{c['method']} {c['endpoint']}")), P(tag(c["before"])), P(tag(c["after"])), P(tag(c["outcome"]))])
        s.append(_table(rows, [W - 90 * mm, 28 * mm, 28 * mm, 34 * mm])); n = 5
    dec = Counter(a["decision"] for a in result["audit"] if "decision" in a)
    planner = next((a["planner"] for a in result["audit"] if a.get("step") == "analyze"), "n/a")
    s += [Paragraph(f"{n}. Agent audit trail", H1),
          P(f"Planner: <b>{esc(planner)}</b>. Plans approved by the policy guard: {dec['APPROVED']}. "
            f"Denied by scope: {dec['DENIED']}. Rejected as invalid (not in the approved catalogue): {dec['REJECTED']}. "
            "The AI planner only proposes tests; a deterministic policy layer validates every target, method and test before execution.", SS["Normal"]),
          Paragraph(f"{n + 1}. Methodology and limitations", H1),
          P("BOLA findings are CONFIRMED only when a control request proves the resource exists and a second account reads it; price findings require the server to charge a tampered amount; rate-limit findings reflect a short burst and carry lower confidence. Items from ZAP are REPORTED, not verified. "
            "Only the approved tests listed in this report were run, against an authorized test environment with synthetic accounts. "
            "A passing result means the tested scenario was not exploitable, not that the endpoint is free of defects.", SS["Normal"])]
    doc.build(s, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
