# verify-app.py (with filtered CSV downloads)

import csv
import io
import os
import re
import time
import uuid
import pandas as pd
import dns.resolver
import smtplib
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
from tempfile import NamedTemporaryFile
os.environ.setdefault("PY3VE_IGNORE_UPDATER", "1")
from validate_email import validate_email
from mailscout import Scout
from metrics import compute_metrics

app = Flask(__name__)
CORS(app)

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")
DISPOSABLE_DOMAINS = {"mailinator.com", "10minutemail.com", "guerrillamail.com"}
ROLE_BASED_PREFIXES = {"info", "support", "admin", "sales", "contact"}
NUMERIC_FIELDS = (
    "Deliveries",
    "Opens",
    "Replies",
    "Bounces",
    "Views",
    "MeetingBooked",
    "Replies_by_sms",
    "Replies_by_LinkedIn",
)

data = {}
# Global MailScout instance and catch-all cache
scout = Scout(
    check_catchall=True,
    num_threads=5,
    smtp_timeout=3,
)

CATCHALL_CACHE = {}
FAILED_SMTP_DOMAINS = {}
SMTP_FAIL_TTL = 1800  # seconds to skip domains that just timed out


def coerce_numeric_fields(df: pd.DataFrame) -> pd.DataFrame:
    """Convert known numeric columns to floats (missing → 0)."""
    for col in NUMERIC_FIELDS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    return df


def base_check_py3(email: str):
    """
    Fast structural + disposable/domain check using py3-validate-email.
    Return (ok: bool, reason: str)
    """
    try:
        ok = validate_email(
            email_address=email,
            check_regex=True,    # RFC-ish syntax
            check_mx=False,      # leave MX + SMTP to MailScout
            use_blacklist=True,  # disposable / bad domains
            smtp_timeout=5,
            dns_timeout=5,
        )
    except Exception:
        # Any error in the library itself: treat as inconclusive
        return False, "py3_error"

    if not ok:
        # Could be format issue or blacklisted domain.
        return False, "py3_format_or_blacklist"

    return True, "py3_ok"

def check_email(email):
    """
    Improved verifier using:
    1) regex (keep your existing quick filter)
    2) disposable / role-based (your rules)
    3) MX check (fast fail)
    4) MailScout catch-all + SMTP deliverability
    """

    # -------------------------------
    # 1. Syntax check (keep your regex)
    # -------------------------------
    if not EMAIL_REGEX.match(email):
        return "invalid", "bad_syntax"

    local, domain = email.split("@", 1)
    domain_lower = domain.lower()

    # -------------------------------
    # 2. Disposable + role-based
    # -------------------------------
    if domain_lower in DISPOSABLE_DOMAINS:
        return "invalid", "disposable_domain"

    if local.lower() in ROLE_BASED_PREFIXES:
        return "risky", "role_based"

    # -------------------------------
    # 3. MX record lookup
    # -------------------------------
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
    except Exception:
        return "invalid", "no_mx"

    # -------------------------------
    # 4. Catch-all detection (MailScout)
    # -------------------------------
    try:
        is_catchall = scout.check_email_catchall(domain)
    except Exception:
        # If catch-all detection fails, keep going
        is_catchall = None

    # -------------------------------
    # 5. SMTP deliverability check (MailScout)
    # -------------------------------
    last_fail = FAILED_SMTP_DOMAINS.get(domain_lower)
    if last_fail and (time.time() - last_fail) < SMTP_FAIL_TTL:
        return "risky", "smtp_domain_timeout"

    try:
        is_deliverable = scout.check_smtp(email)
    except Exception:
        # If the SMTP attempt does not run (timeout, network block),
        # we classify as risky but not invalid.
        FAILED_SMTP_DOMAINS[domain_lower] = time.time()
        return "risky", "smtp_error"

    # -------------------------------
    # 6. Interpret MailScout results
    # -------------------------------
    # Case A: SMTP says deliverable
    if is_deliverable:
        if is_catchall:
            # Domain is catch-all → mailbox may not exist
            return "risky", "domain_accepts_all"
        else:
            return "valid", "smtp_ok"

    # Case B: SMTP says NOT deliverable
    # If domain is catch-all, we cannot trust SMTP
    if is_catchall:
        return "risky", "catchall_uncertain"

    # If not catch-all and SMTP says false → consider invalid
    return "invalid", "smtp_not_deliverable"

@app.route('/verify', methods=['POST'])
def verify():
    job_id = str(uuid.uuid4())
    file = request.files['file']
    content = file.read().decode('utf-8')
    reader = list(csv.DictReader(io.StringIO(content)))
    original_rows = [row.copy() for row in reader]
    total = len(reader)
    email_field = next((f for f in reader[0].keys() if f.lower().strip() == 'email'), None)

    output = io.StringIO()
    fieldnames = list(reader[0].keys()) + ['status', 'reason']
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    data[job_id] = {
        "progress": 0,
        "row": 0,
        "total": total,
        "log": "",
        "cancel": False,
        "output": output,
        "writer": writer,
        "records": reader,
        "ground_truth": original_rows,
        "email_field": email_field,
        "metrics": None,
        "metrics_error": None,
        "filename": file.filename
    }

    def run():
        try:
            for i, row in enumerate(reader, start=1):
                if data[job_id]['cancel']:
                    data[job_id]['log'] = f"\u274c Canceled job {job_id}"
                    break
                email = (row.get(email_field) or '').strip()
                if not email:
                    status, reason = 'invalid', 'empty_email'
                else:
                    try:
                        status, reason = check_email(email)
                    except Exception as e:
                        print(f"Error checking {email}: {e}")
                        status, reason = 'risky', 'check_error'
                row['status'], row['reason'] = status, reason
                writer.writerow(row)
                percent = int((i / total) * 100)
                data[job_id].update({"progress": percent, "row": i,
                                     "log": f"\u2705 {email} → {status} ({reason})"})
        except Exception as e:
            print(f"FATAL ERROR in run(): {e}")
            import traceback
            traceback.print_exc()
            data[job_id]['log'] = f"\u274c Error: {str(e)}"
        output = data[job_id]['output']
        output.seek(0)
        temp = NamedTemporaryFile(delete=False, suffix=".csv", mode='w+')
        temp.write(output.read())
        temp.flush()
        temp.seek(0)
        data[job_id]['file_path'] = temp.name
        try:
            test_df = coerce_numeric_fields(pd.DataFrame(data[job_id]['ground_truth']))
            results_df = coerce_numeric_fields(pd.DataFrame(reader))
            data[job_id]['metrics'] = compute_metrics(test_df, results_df)
        except Exception as exc:
            data[job_id]['metrics_error'] = str(exc)


    import threading
    threading.Thread(target=run).start()

    return jsonify({"job_id": job_id})

@app.route('/progress')
def progress():
    job_id = request.args.get("job_id")
    d = data.get(job_id, {})
    return jsonify({"percent": d.get("progress", 0), "row": d.get("row", 0), "total": d.get("total", 0)})

@app.route('/log')
def log():
    job_id = request.args.get("job_id")
    return Response(data.get(job_id, {}).get("log", ""), mimetype='text/plain')

@app.route('/cancel', methods=['POST'])
def cancel():
    job_id = request.args.get("job_id")
    if job_id in data:
        data[job_id]['cancel'] = True
    return '', 204

@app.route('/download')
def download():
    job_id = request.args.get("job_id")
    filter_type = request.args.get("type", "all")
    job = data.get(job_id)
    if not job:
        return "Invalid job ID", 404

    job['output'].seek(0)
    reader = list(csv.DictReader(job['output']))

    if filter_type == "valid":
        filtered = [row for row in reader if row['status'] == 'valid']
    elif filter_type == "risky":
        filtered = [row for row in reader if row['status'] == 'risky']
    elif filter_type == "risky_invalid":
        filtered = [row for row in reader if row['status'] in ('risky', 'invalid')]
    else:
        filtered = reader

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=reader[0].keys())
    writer.writeheader()
    for row in filtered:
        writer.writerow(row)

    output.seek(0)
    download_name = f"{filter_type}-galadon-{job['filename']}"
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={"Content-Disposition": f"attachment; filename={download_name}"}
    )

@app.route('/metrics')
def metrics_endpoint():
    job_id = request.args.get("job_id")
    job = data.get(job_id)
    if not job:
        return jsonify({"error": "Invalid job ID"}), 404
    if job.get("metrics") is not None:
        return jsonify(job["metrics"])
    if job.get("metrics_error"):
        return jsonify({"error": job["metrics_error"]}), 500
    return jsonify({"status": "pending"}), 202

if __name__ == '__main__':
    app.run(debug=True, port=5050)
