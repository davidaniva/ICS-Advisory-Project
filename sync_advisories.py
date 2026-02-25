#!/usr/bin/env python3
"""Pull latest CSV data from git and sync changes into the SQLite database.

Compares the master CSV against the existing DB to determine inserts and
updates, then executes them as tracked jobs.
"""

import csv
import hashlib
import json
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from migrate_csv_to_sqlite import DB_PATH, CSV_PATH, SCHEMA, parse_multi

JOBS_SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_jobs (
    job_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    git_commit  TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    inserts     INTEGER DEFAULT 0,
    updates     INTEGER DEFAULT 0,
    deletes     INTEGER DEFAULT 0,
    errors      INTEGER DEFAULT 0,
    details     TEXT
);

CREATE TABLE IF NOT EXISTS sync_job_items (
    item_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES sync_jobs(job_id),
    icsad_id    INTEGER NOT NULL,
    action      TEXT NOT NULL,
    diff        TEXT
);

CREATE INDEX IF NOT EXISTS idx_job_items_job ON sync_job_items(job_id);
"""

ADVISORY_FIELDS = (
    "original_release", "last_updated", "year", "advisory_number",
    "advisory_title", "vendor", "product", "products_affected",
    "cumulative_cvss", "cvss_severity", "product_distribution",
    "company_headquarters", "license",
)


def git_pull():
    """Pull latest changes from origin main. Returns the current HEAD commit."""
    repo_root = Path(__file__).parent
    try:
        subprocess.run(
            ["git", "pull", "origin", "main"],
            cwd=repo_root, capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Warning: git pull failed: {e.stderr.strip()}", file=sys.stderr)

    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root, capture_output=True, text=True,
    )
    return result.stdout.strip()


def row_hash(row_dict):
    """Hash all fields of a CSV row for change detection."""
    raw = json.dumps(row_dict, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_csv_row(row):
    """Convert a CSV row dict into the tuple of advisory field values."""
    cvss_raw = row["Cumulative_CVSS"].strip()
    cvss = float(cvss_raw) if cvss_raw and cvss_raw.replace(".", "").isdigit() else None
    return {
        "icsad_id": int(row["icsad_ID"]),
        "original_release": row["Original_Release_Date"].strip(),
        "last_updated": row["Last_Updated"].strip(),
        "year": int(row["Year"]),
        "advisory_number": row["ICS-CERT_Number"].strip(),
        "advisory_title": row["ICS-CERT_Advisory_Title"].strip(),
        "vendor": row["Vendor"].strip(),
        "product": row["Product"].strip(),
        "products_affected": row["Products_Affected"].strip(),
        "cumulative_cvss": cvss,
        "cvss_severity": row["CVSS_Severity"].strip(),
        "product_distribution": row["Product_Distribution"].strip(),
        "company_headquarters": row["Company_Headquarters"].strip(),
        "license": row.get("License", "").strip(),
        "cves": parse_multi(row["CVE_Number"], ","),
        "cwes": parse_multi(row["CWE_Number"], ","),
        "sectors": parse_multi(row["Critical_Infrastructure_Sector"], ";"),
    }


def get_existing_row(conn, icsad_id):
    """Fetch an existing advisory and its related data from the DB."""
    adv = conn.execute(
        "SELECT * FROM advisories WHERE icsad_id = ?", (icsad_id,)
    ).fetchone()
    if not adv:
        return None

    cves = [r[0] for r in conn.execute(
        "SELECT cve FROM advisory_cves WHERE icsad_id = ? ORDER BY cve", (icsad_id,)
    )]
    cwes = [r[0] for r in conn.execute(
        "SELECT cwe FROM advisory_cwes WHERE icsad_id = ? ORDER BY cwe", (icsad_id,)
    )]
    sectors = [r[0] for r in conn.execute(
        "SELECT sector FROM advisory_sectors WHERE icsad_id = ? ORDER BY sector",
        (icsad_id,),
    )]

    cols = [desc[0] for desc in conn.execute("SELECT * FROM advisories LIMIT 0").description]
    row_dict = dict(zip(cols, adv))
    row_dict["cves"] = cves
    row_dict["cwes"] = cwes
    row_dict["sectors"] = sectors
    return row_dict


def diff_rows(existing, incoming):
    """Return a dict of changed fields between existing DB row and incoming CSV row."""
    changes = {}
    for field in ADVISORY_FIELDS:
        old_val = existing.get(field)
        new_val = incoming.get(field)
        if old_val != new_val:
            changes[field] = {"old": old_val, "new": new_val}

    if sorted(existing.get("cves", [])) != sorted(incoming.get("cves", [])):
        changes["cves"] = {"old": existing["cves"], "new": incoming["cves"]}
    if sorted(existing.get("cwes", [])) != sorted(incoming.get("cwes", [])):
        changes["cwes"] = {"old": existing["cwes"], "new": incoming["cwes"]}
    if sorted(existing.get("sectors", [])) != sorted(incoming.get("sectors", [])):
        changes["sectors"] = {"old": existing["sectors"], "new": incoming["sectors"]}

    return changes


def upsert_advisory(conn, parsed):
    """Insert or replace an advisory and its related data."""
    icsad_id = parsed["icsad_id"]

    conn.execute(
        """INSERT OR REPLACE INTO advisories
           (icsad_id, original_release, last_updated, year, advisory_number,
            advisory_title, vendor, product, products_affected,
            cumulative_cvss, cvss_severity, product_distribution,
            company_headquarters, license)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            icsad_id, parsed["original_release"], parsed["last_updated"],
            parsed["year"], parsed["advisory_number"], parsed["advisory_title"],
            parsed["vendor"], parsed["product"], parsed["products_affected"],
            parsed["cumulative_cvss"], parsed["cvss_severity"],
            parsed["product_distribution"], parsed["company_headquarters"],
            parsed["license"],
        ),
    )

    # Replace related rows
    conn.execute("DELETE FROM advisory_cves WHERE icsad_id = ?", (icsad_id,))
    conn.execute("DELETE FROM advisory_cwes WHERE icsad_id = ?", (icsad_id,))
    conn.execute("DELETE FROM advisory_sectors WHERE icsad_id = ?", (icsad_id,))

    for cve in parsed["cves"]:
        conn.execute("INSERT INTO advisory_cves (icsad_id, cve) VALUES (?, ?)", (icsad_id, cve))
    for cwe in parsed["cwes"]:
        conn.execute("INSERT INTO advisory_cwes (icsad_id, cwe) VALUES (?, ?)", (icsad_id, cwe))
    for sector in parsed["sectors"]:
        conn.execute("INSERT INTO advisory_sectors (icsad_id, sector) VALUES (?, ?)", (icsad_id, sector))


def sync():
    now = datetime.now(timezone.utc).isoformat()

    # Pull latest data
    print("Pulling latest data from origin...")
    git_commit = git_pull()
    print(f"  HEAD: {git_commit[:10]}")

    if not CSV_PATH.exists():
        print(f"Error: CSV not found at {CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    # Ensure DB and schema exist
    needs_full_load = not DB_PATH.exists()
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    conn.executescript(JOBS_SCHEMA)

    # Start job
    cur = conn.execute(
        "INSERT INTO sync_jobs (started_at, git_commit, status) VALUES (?, ?, 'running')",
        (now, git_commit),
    )
    job_id = cur.lastrowid

    # Read CSV
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        csv_rows = {int(r["icsad_ID"]): r for r in csv.DictReader(f)}

    print(f"  CSV rows: {len(csv_rows)}")

    # Get existing IDs
    existing_ids = set()
    if not needs_full_load:
        existing_ids = {r[0] for r in conn.execute("SELECT icsad_id FROM advisories")}
    print(f"  Existing DB rows: {len(existing_ids)}")

    inserts = 0
    updates = 0
    deletes = 0
    errors = 0

    # Detect inserts and updates
    for icsad_id, raw_row in csv_rows.items():
        try:
            parsed = parse_csv_row(raw_row)

            if icsad_id not in existing_ids:
                # New advisory
                upsert_advisory(conn, parsed)
                conn.execute(
                    "INSERT INTO sync_job_items (job_id, icsad_id, action) VALUES (?, ?, 'insert')",
                    (job_id, icsad_id),
                )
                inserts += 1
            else:
                # Check for changes
                existing = get_existing_row(conn, icsad_id)
                changes = diff_rows(existing, parsed)
                if changes:
                    upsert_advisory(conn, parsed)
                    conn.execute(
                        "INSERT INTO sync_job_items (job_id, icsad_id, action, diff) VALUES (?, ?, 'update', ?)",
                        (job_id, icsad_id, json.dumps(changes)),
                    )
                    updates += 1
        except Exception as e:
            print(f"  Error processing icsad_id={icsad_id}: {e}", file=sys.stderr)
            errors += 1

    # Detect deletes (in DB but no longer in CSV)
    removed_ids = existing_ids - set(csv_rows.keys())
    for icsad_id in removed_ids:
        conn.execute("DELETE FROM advisory_cves WHERE icsad_id = ?", (icsad_id,))
        conn.execute("DELETE FROM advisory_cwes WHERE icsad_id = ?", (icsad_id,))
        conn.execute("DELETE FROM advisory_sectors WHERE icsad_id = ?", (icsad_id,))
        conn.execute("DELETE FROM advisories WHERE icsad_id = ?", (icsad_id,))
        conn.execute(
            "INSERT INTO sync_job_items (job_id, icsad_id, action) VALUES (?, ?, 'delete')",
            (job_id, icsad_id),
        )
        deletes += 1

    # Finalize job
    finished_at = datetime.now(timezone.utc).isoformat()
    status = "completed" if errors == 0 else "completed_with_errors"
    conn.execute(
        """UPDATE sync_jobs
           SET finished_at = ?, status = ?, inserts = ?, updates = ?, deletes = ?, errors = ?
           WHERE job_id = ?""",
        (finished_at, status, inserts, updates, deletes, errors, job_id),
    )

    conn.commit()
    conn.close()

    print(f"\nSync job #{job_id} {status}:")
    print(f"  Inserts: {inserts}")
    print(f"  Updates: {updates}")
    print(f"  Deletes: {deletes}")
    if errors:
        print(f"  Errors:  {errors}")


if __name__ == "__main__":
    sync()
