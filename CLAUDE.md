# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The ICS Advisory Project is a data-only repository (no build/lint/test tooling) that curates CISA ICS (Industrial Control Systems) Advisories as CSV files for vulnerability analysis in the OT/ICS community. The data feeds the ICS Advisory Dashboard at icsadvisoryproject.com.

## Repository Structure

- `ICS-CERT_ADV/` — All advisory CSV data
  - `CISA_ICS_ADV_Master.csv` — Consolidated master file containing all advisories (~3700+ rows)
  - Per-year CSVs: `ICS-CERT_ADV_{YEAR}_*.csv` (2010–2022) and `CISA_ICS_ADV_{YEAR}_*.csv` (2023+) — the naming change reflects CISA's rebranding from ICS-CERT
  - `ICS-CERT_ADV_Archive/` — Historical snapshots of the master CSV (195+ dated copies)

## CSV Schema

All CSVs share these columns (in order):

`icsad_ID`, `Original_Release_Date`, `Last_Updated`, `Year`, `ICS-CERT_Number`, `ICS-CERT_Advisory_Title`, `Vendor`, `Product`, `Products_Affected`, `CVE_Number`, `Cumulative_CVSS`, `CVSS_Severity`, `CWE_Number`, `Critical_Infrastructure_Sector`, `Product_Distribution`, `Company_Headquarters`

The 2023+ files also include a `License` column at the end.

Key data notes:
- `CVE_Number` and `CWE_Number` fields may contain multiple values (comma- or semicolon-delimited)
- `Critical_Infrastructure_Sector` may list multiple sectors separated by semicolons
- `CVSS_Severity` values: Critical, High, Medium, Low
- `ICS-CERT_Number` format: `ICSA-YY-DDD-NN` (advisory) or `ICSMA-YY-DDD-NN` (medical advisory)

## Data Conventions

- Year files contain advisories only for that calendar year; the master file aggregates all years
- Archive snapshots are named `CISA_ICS_ADV_Master_YYYYMMDD.csv` with the date of the snapshot
- The date suffix in per-year filenames (e.g., `_2_24_26`) represents the last update date (month_day_year in 2-digit format)

## License

Open Database License (ODbL) v1.0. Attribution and share-alike are required for any public use or redistribution.
