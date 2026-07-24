import hashlib
import json
import os
import re
from datetime import datetime, timezone
from difflib import SequenceMatcher
from email.parser import BytesParser
from email import policy
from io import BytesIO
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, redirect, render_template, request, Response, url_for

main = Blueprint("main", __name__)


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


def extract_body(message) -> str:
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            if content_type in {"text/plain", "text/html"}:
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = part.get_payload()
                if isinstance(payload, bytes):
                    return payload.decode("utf-8", errors="replace")
                return str(payload)
        return ""

    payload = message.get_payload(decode=True)
    if payload is None:
        payload = message.get_payload()
    if isinstance(payload, bytes):
        return payload.decode("utf-8", errors="replace")
    return str(payload)


SHORTENER_DOMAINS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "lnkd.in",
    "is.gd",
    "rb.gy",
    "buff.ly",
    "rebrand.ly",
    "bl.ink",
    "tiny.one",
    "t.ly",
}
COMMON_BRANDS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "office.com",
    "dropbox.com",
    "github.com",
    "netflix.com",
    "facebook.com",
    "linkedin.com",
    "icloud.com",
    "outlook.com",
    "adobe.com",
    "bankofamerica.com",
]
URL_RE = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.IGNORECASE)
DANGEROUS_EXTENSIONS = {
    "exe",
    "dll",
    "bat",
    "cmd",
    "com",
    "scr",
    "js",
    "jar",
    "vbs",
    "ps1",
    "hta",
    "msi",
    "iso",
    "zip",
    "rar",
    "7z",
    "pdf",
}


def extract_urls(text: str):
    urls = []
    seen = set()
    for match in URL_RE.finditer(text or ""):
        candidate = match.group(0).strip().rstrip(".,;:!?)]}")
        if candidate.startswith("www."):
            candidate = f"http://{candidate}"
        if candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)
    return urls


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().lstrip("www.")


def is_ip_host(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def is_shortened_link(host: str) -> bool:
    return host in SHORTENER_DOMAINS


def is_typosquatting(url: str) -> tuple[bool, str]:
    host = get_hostname(url)
    if not host:
        return False, ""
    parts = host.split(".")
    if len(parts) < 2:
        return False, ""
    base_domain = ".".join(parts[-2:])
    for brand in COMMON_BRANDS:
        if base_domain == brand:
            return False, ""
        if SequenceMatcher(None, base_domain, brand).ratio() >= 0.85:
            return True, brand
    return False, ""


def analyze_url(url: str):
    host = get_hostname(url)
    reasons = []
    score = 0

    if is_shortened_link(host):
        reasons.append("Shortened link")
        score += 45

    if is_ip_host(host):
        reasons.append("IP-based URL")
        score += 40

    typosquatting, brand = is_typosquatting(url)
    if typosquatting:
        reasons.append(f"Typosquatting (looks like {brand})")
        score += 45

    if score >= 70:
        risk_level = "High"
    elif score >= 35:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "url": url,
        "host": host,
        "risk_score": min(score, 100),
        "risk_level": risk_level,
        "reasons": reasons,
        "suspicious": bool(reasons),
    }


def analyze_attachment(part):
    filename = part.get_filename() or "unnamed"
    payload = part.get_payload(decode=True)
    if payload is None:
        payload = b""
    if not isinstance(payload, bytes):
        payload = str(payload).encode("utf-8", errors="replace")

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    dangerous = ext in DANGEROUS_EXTENSIONS
    size = len(payload)
    sha256 = hashlib.sha256(payload).hexdigest()
    md5 = hashlib.md5(payload).hexdigest()

    return {
        "filename": filename,
        "extension": ext,
        "size_bytes": size,
        "size_human": f"{size} bytes",
        "sha256": sha256,
        "md5": md5,
        "dangerous": dangerous,
        "risk_level": "High" if dangerous else "Low",
    }


def evaluate_authentication(message):
    auth_header = message.get("Authentication-Results", "") or message.get("ARC-Authentication-Results", "")
    received_spf = message.get("Received-SPF", "")
    dkim_signature = message.get("DKIM-Signature", "")

    results = []

    def add_result(name, value, detail):
        if not value:
            return
        normalized = value.lower()
        if normalized == "pass":
            status = "Passed"
            summary = f"{name} passed based on the message headers."
        elif normalized in {"fail", "softfail", "temperror", "permerror"}:
            status = "Failed"
            summary = f"{name} failed or was not accepted based on the message headers."
        else:
            status = "Neutral"
            summary = f"{name} returned a non-passing result: {value}."
        results.append((name, status, summary, detail))

    if auth_header:
        for protocol, pattern in (("SPF", r"\bspf=(pass|fail|softfail|neutral|temperror|permerror)\b"), ("DKIM", r"\bdkim=(pass|fail|softfail|neutral|temperror|permerror)\b"), ("DMARC", r"\bdmarc=(pass|fail|softfail|neutral|temperror|permerror)\b")):
            match = re.search(pattern, auth_header, re.IGNORECASE)
            if match:
                add_result(protocol, match.group(1), auth_header)
    if received_spf:
        spf_match = re.search(r"\b(pass|fail|softfail|neutral|temperror|permerror)\b", received_spf, re.IGNORECASE)
        if spf_match:
            add_result("SPF", spf_match.group(1), received_spf)
    if dkim_signature:
        dkim_match = re.search(r"\b(pass|fail|softfail|neutral|temperror|permerror)\b", dkim_signature, re.IGNORECASE)
        if dkim_match:
            add_result("DKIM", dkim_match.group(1), dkim_signature)

    if not results:
        results = [
            ("SPF", "Not available", "No SPF result was found in the headers.", ""),
            ("DKIM", "Not available", "No DKIM result was found in the headers.", ""),
            ("DMARC", "Not available", "No DMARC result was found in the headers.", ""),
        ]

    passed = sum(1 for _, status, _, _ in results if status == "Passed")
    failed = sum(1 for _, status, _, _ in results if status == "Failed")
    overall_status = "Passed" if passed > 0 and failed == 0 and len(results) >= 3 and all(status == "Passed" for _, status, _, _ in results if _ != "SPF" or False) else "Failed" if failed > 0 else "Inconclusive"

    if overall_status == "Passed" and any(status == "Not available" for _, status, _, _ in results):
        overall_status = "Inconclusive"

    overall_summary = "All available authentication checks passed." if overall_status == "Passed" else "At least one authentication check failed or was not available." if overall_status == "Failed" else "Authentication could not be fully determined from the headers provided."

    return results, overall_status, overall_summary


def extract_iocs(message, body, attachment_details):
    text = "\n".join([body, message.get("Subject", ""), message.get("From", ""), message.get("To", "")])
    domains = []
    ips = []
    urls = []
    hashes = []
    emails = []

    domain_pattern = re.compile(r"(?<![\w./-])([a-z0-9.-]+\.[a-z]{2,})(?![\w.-])", re.IGNORECASE)
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    email_pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    sha_pattern = re.compile(r"\b(?:sha(?:256|1)?|md5):?\s*([a-fA-F0-9]{32,64})\b")
    hash_pattern = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

    for match in domain_pattern.finditer(text):
        domain = match.group(1).lower()
        if domain not in domains:
            domains.append(domain)
    for match in ip_pattern.finditer(text):
        ip = match.group(0)
        if ip not in ips:
            ips.append(ip)
    for url in extract_urls(text):
        if url not in urls:
            urls.append(url)
    for match in email_pattern.finditer(text):
        email = match.group(0).lower()
        if email not in emails:
            emails.append(email)
    for match in sha_pattern.finditer(text):
        hashes.append(match.group(1).lower())
    for match in hash_pattern.finditer(text):
        value = match.group(1).lower()
        if value not in hashes:
            hashes.append(value)
    for attachment in attachment_details:
        hashes.append(attachment["sha256"])
        hashes.append(attachment["md5"])

    seen_hashes = []
    for value in hashes:
        if value not in seen_hashes:
            seen_hashes.append(value)

    return {
        "domains": domains,
        "ips": ips,
        "urls": urls,
        "hashes": seen_hashes,
        "emails": emails,
    }


def build_report_data(headers, body, auth_results, overall_status, overall_summary, urls, attachment_details, iocs, filename, saved_path):
    suspicious_urls = [item for item in urls if item.get("suspicious")]
    dangerous_attachments = [item for item in attachment_details if item.get("dangerous")]
    high_risk = overall_status == "Failed" or bool(suspicious_urls) or bool(dangerous_attachments)
    risk_level = "High" if high_risk else "Medium" if suspicious_urls or dangerous_attachments else "Low"

    threat_summary = []
    if overall_status == "Failed":
        threat_summary.append("Authentication checks indicate a failed or suspicious validation outcome.")
    if suspicious_urls:
        threat_summary.append("Suspicious URLs were extracted from the message body.")
    if dangerous_attachments:
        threat_summary.append("Dangerous file extensions were detected in attachments.")
    if not threat_summary:
        threat_summary.append("No obvious indicators of compromise were detected from the available message content.")

    recommendations = []
    if suspicious_urls:
        recommendations.append("Block or investigate the extracted URLs and verify them with a sandbox or URL reputation service.")
    if dangerous_attachments:
        recommendations.append("Quarantine attachments and scan them with endpoint protection before opening.")
    if overall_status == "Failed":
        recommendations.append("Treat the sender as untrusted until authentication is verified with the sending domain.")
    recommendations.append("Review the sender, recipients, and headers for further context and preserve the message for forensic review.")

    timeline = []
    for key, value in headers:
        if key == "Date" and value:
            timeline.append((value, "Message date header recorded"))
            break
    timeline.append((datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"), "Email analyzed and report generated"))

    return {
        "filename": filename,
        "saved_path": saved_path,
        "threat_summary": " ".join(threat_summary),
        "indicators": {
            "domains": iocs.get("domains", []),
            "ips": iocs.get("ips", []),
            "urls": iocs.get("urls", []),
            "hashes": iocs.get("hashes", []),
            "emails": iocs.get("emails", []),
        },
        "risk_level": risk_level,
        "recommendations": recommendations,
        "timeline": timeline,
        "auth_overview": overall_summary,
        "body_preview": body[:1200],
    }


def create_report_pdf(report_data):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, ListFlowable, ListItem

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(name="TitleStyle", parent=styles["Title"], fontSize=16, leading=22, textColor=colors.HexColor("#0f172a"), spaceAfter=12)
    heading_style = ParagraphStyle(name="HeadingStyle", parent=styles["Heading2"], fontSize=12, leading=14, textColor=colors.HexColor("#1d4ed8"), spaceAfter=8)
    body_style = ParagraphStyle(name="BodyStyle", parent=styles["BodyText"], fontSize=10, leading=13, textColor=colors.HexColor("#111827"), spaceAfter=6)

    story = []
    story.append(Paragraph("Email Threat Investigation Report", title_style))
    story.append(Paragraph(f"Filename: {report_data.get('filename', 'unknown')}", body_style))
    story.append(Spacer(1, 6))

    story.append(Paragraph("Threat Summary", heading_style))
    story.append(Paragraph(report_data.get("threat_summary", "No summary available."), body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Indicators", heading_style))
    indicator_items = []
    for name, values in report_data.get("indicators", {}).items():
        if values:
            indicator_items.append(Paragraph(f"<b>{name.title()}</b>: {', '.join(values)}", body_style))
    if not indicator_items:
        indicator_items.append(Paragraph("No indicators extracted.", body_style))
    story.extend(indicator_items)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Risk Level", heading_style))
    story.append(Paragraph(report_data.get("risk_level", "Low"), body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Recommendations", heading_style))
    rec_items = [Paragraph(item, body_style) for item in report_data.get("recommendations", [])]
    story.extend(rec_items)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Timeline", heading_style))
    for timestamp, event in report_data.get("timeline", []):
        story.append(Paragraph(f"- {timestamp}: {event}", body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Authentication Overview", heading_style))
    story.append(Paragraph(report_data.get("auth_overview", "No authentication context available."), body_style))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Body Preview", heading_style))
    story.append(Paragraph(report_data.get("body_preview", "")[:3000], body_style))

    doc.build(story)
    return buffer.getvalue()


def parse_email(file_bytes: bytes):
    message = BytesParser(policy=policy.default).parsebytes(file_bytes)
    headers = [
        ("From", message.get("From", "")),
        ("To", message.get("To", "")),
        ("Reply-To", message.get("Reply-To", "")),
        ("Subject", message.get("Subject", "")),
        ("Date", message.get("Date", "")),
        ("Received", "\n".join(message.get_all("Received", []))),
        ("Return Path", message.get("Return-Path", "")),
        ("Message ID", message.get("Message-ID", "")),
    ]
    body = extract_body(message)
    attachments = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
    auth_results, overall_status, overall_summary = evaluate_authentication(message)
    text_for_urls = "\n".join([body, message.get("Subject", ""), message.get("From", ""), message.get("To", "")])
    urls = [analyze_url(url) for url in extract_urls(text_for_urls)]
    attachment_details = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_filename():
            attachment_details.append(analyze_attachment(part))
    iocs = extract_iocs(message, body, attachment_details)
    return headers, body, attachments, auth_results, overall_status, overall_summary, urls, attachment_details, iocs


@main.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files.get("email_file")
        if not file or file.filename == "":
            flash("Please choose an .eml file to upload.", "error")
            return redirect(url_for("main.index"))

        if not allowed_file(file.filename):
            flash("Only .eml files are supported.", "error")
            return redirect(url_for("main.index"))

        file_bytes = file.read()
        filename = file.filename.rsplit("/", 1)[-1]
        safe_name = filename
        save_path = os.path.join(current_app.config["UPLOAD_FOLDER"], safe_name)

        with open(save_path, "wb") as handle:
            handle.write(file_bytes)

        headers, body, attachments, auth_results, overall_status, overall_summary, urls, attachment_details, iocs = parse_email(file_bytes)
        report_data = build_report_data(
            headers,
            body,
            auth_results,
            overall_status,
            overall_summary,
            urls,
            attachment_details,
            iocs,
            safe_name,
            save_path,
        )
        return render_template(
            "result.html",
            filename=safe_name,
            headers=headers,
            body=body,
            attachments=attachments,
            auth_results=auth_results,
            overall_status=overall_status,
            overall_summary=overall_summary,
            urls=urls,
            attachment_details=attachment_details,
            iocs=iocs,
            report_data=report_data,
            report_data_json=json.dumps(report_data),
            saved_path=save_path,
        )

    return render_template("index.html")


@main.route("/generate-report", methods=["POST"])
def generate_report():
    report_json = request.form.get("report_data", "")
    if not report_json:
        flash("No report data available to export.", "error")
        return redirect(url_for("main.index"))

    try:
        report_data = json.loads(report_json)
    except json.JSONDecodeError:
        flash("The report data could not be parsed.", "error")
        return redirect(url_for("main.index"))

    pdf_bytes = create_report_pdf(report_data)
    response = Response(pdf_bytes, mimetype="application/pdf")
    filename = report_data.get("filename", "investigation_report")
    clean_name = os.path.splitext(filename)[0]
    response.headers["Content-Disposition"] = f"attachment; filename={clean_name}_report.pdf"
    return response


@main.route("/export-iocs", methods=["POST"])
def export_iocs():
    if not request.form.get("ioc_data"):
        flash("No IOC data available to export.", "error")
        return redirect(url_for("main.index"))

    payload = request.form.get("ioc_data", "")
    response = Response(payload, mimetype="text/plain")
    response.headers["Content-Disposition"] = "attachment; filename=ioc_list.txt"
    return response
