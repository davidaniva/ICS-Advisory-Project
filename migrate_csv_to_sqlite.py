#!/usr/bin/env python3
"""Migrate CISA ICS Advisory master CSV into a normalized SQLite database."""

import csv
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).parent / "ics_advisories.db"
CSV_PATH = Path(__file__).parent / "ICS-CERT_ADV" / "CISA_ICS_ADV_Master.csv"

SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    icsad_id            INTEGER PRIMARY KEY,
    original_release    TEXT,
    last_updated        TEXT,
    year                INTEGER,
    advisory_number     TEXT NOT NULL,
    advisory_title      TEXT,
    vendor              TEXT,
    product             TEXT,
    products_affected   TEXT,
    cumulative_cvss     REAL,
    cvss_severity       TEXT,
    product_distribution TEXT,
    company_headquarters TEXT,
    license             TEXT
);

CREATE TABLE IF NOT EXISTS advisory_cves (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    icsad_id    INTEGER NOT NULL REFERENCES advisories(icsad_id),
    cve         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advisory_cwes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    icsad_id    INTEGER NOT NULL REFERENCES advisories(icsad_id),
    cwe         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advisory_sectors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    icsad_id    INTEGER NOT NULL REFERENCES advisories(icsad_id),
    sector      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cves_icsad    ON advisory_cves(icsad_id);
CREATE INDEX IF NOT EXISTS idx_cves_cve      ON advisory_cves(cve);
CREATE INDEX IF NOT EXISTS idx_cwes_icsad    ON advisory_cwes(icsad_id);
CREATE INDEX IF NOT EXISTS idx_cwes_cwe      ON advisory_cwes(cwe);
CREATE INDEX IF NOT EXISTS idx_sectors_icsad ON advisory_sectors(icsad_id);
CREATE INDEX IF NOT EXISTS idx_sectors_name  ON advisory_sectors(sector);
CREATE INDEX IF NOT EXISTS idx_adv_vendor    ON advisories(vendor);
CREATE INDEX IF NOT EXISTS idx_adv_year      ON advisories(year);
CREATE INDEX IF NOT EXISTS idx_adv_severity  ON advisories(cvss_severity);
"""


def parse_multi(value, delimiter=","):
    """Split a delimited field into stripped, non-empty values."""
    return [v.strip() for v in value.split(delimiter) if v.strip()]


def migrate():
    if not CSV_PATH.exists():
        print(f"Error: CSV not found at {CSV_PATH}", file=sys.stderr)
        sys.exit(1)

    # Remove existing DB to do a clean migration
    if DB_PATH.exists():
        DB_PATH.unlink()

    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)

    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    adv_count = 0
    cve_count = 0
    cwe_count = 0
    sector_count = 0

    for row in rows:
        icsad_id = int(row["icsad_ID"])
        cvss_raw = row["Cumulative_CVSS"].strip()
        cvss = float(cvss_raw) if cvss_raw and cvss_raw.replace(".", "").isdigit() else None

        conn.execute(
            """INSERT INTO advisories
               (icsad_id, original_release, last_updated, year, advisory_number,
                advisory_title, vendor, product, products_affected,
                cumulative_cvss, cvss_severity, product_distribution,
                company_headquarters, license)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                icsad_id,
                row["Original_Release_Date"].strip(),
                row["Last_Updated"].strip(),
                int(row["Year"]),
                row["ICS-CERT_Number"].strip(),
                row["ICS-CERT_Advisory_Title"].strip(),
                row["Vendor"].strip(),
                row["Product"].strip(),
                row["Products_Affected"].strip(),
                cvss,
                row["CVSS_Severity"].strip(),
                row["Product_Distribution"].strip(),
                row["Company_Headquarters"].strip(),
                row.get("License", "").strip(),
            ),
        )
        adv_count += 1

        for cve in parse_multi(row["CVE_Number"], ","):
            conn.execute(
                "INSERT INTO advisory_cves (icsad_id, cve) VALUES (?, ?)",
                (icsad_id, cve),
            )
            cve_count += 1

        for cwe in parse_multi(row["CWE_Number"], ","):
            conn.execute(
                "INSERT INTO advisory_cwes (icsad_id, cwe) VALUES (?, ?)",
                (icsad_id, cwe),
            )
            cwe_count += 1

        for sector in parse_multi(row["Critical_Infrastructure_Sector"], ";"):
            conn.execute(
                "INSERT INTO advisory_sectors (icsad_id, sector) VALUES (?, ?)",
                (icsad_id, sector),
            )
            sector_count += 1

    conn.commit()
    conn.close()

    print(f"Migration complete: {DB_PATH}")
    print(f"  Advisories: {adv_count}")
    print(f"  CVE entries: {cve_count}")
    print(f"  CWE entries: {cwe_count}")
    print(f"  Sector entries: {sector_count}")


if __name__ == "__main__":
    migrate()
