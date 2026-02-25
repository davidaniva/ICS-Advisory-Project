#!/usr/bin/env python3
"""Natural-language Q&A over the ICS Advisory SQLite database.

Bring Your Own Key (BYOK) — supply an OpenAI or Anthropic API key and ask
questions about ICS/OT advisories in plain English.  The LLM translates your
question into SQL, executes it (read-only) against the local SQLite database,
and returns a human-readable answer.

Usage
-----
# Interactive REPL (default)
  OPENAI_API_KEY=sk-... python query_advisories.py
  ANTHROPIC_API_KEY=sk-ant-... python query_advisories.py --provider anthropic

# Single-shot
  python query_advisories.py --query "How many critical advisories were published in 2024?"

# Override model
  python query_advisories.py --provider openai --model gpt-4o-mini

Environment variables
---------------------
  OPENAI_API_KEY      Required when provider is openai (default provider).
  ANTHROPIC_API_KEY   Required when provider is anthropic.

These can also be passed via --api-key on the command line.
"""

import argparse
import json
import os
import re
import sqlite3
import sys
import textwrap
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

DB_PATH = Path(__file__).parent / "ics_advisories.db"

# ---------------------------------------------------------------------------
# Database schema summary sent to the LLM as context
# ---------------------------------------------------------------------------

SCHEMA_CONTEXT = """\
SQLite database: ics_advisories.db

TABLE advisories (
    icsad_id            INTEGER PRIMARY KEY,  -- unique advisory ID
    original_release    TEXT,   -- date string MM/DD/YYYY
    last_updated        TEXT,   -- date string MM/DD/YYYY
    year                INTEGER,
    advisory_number     TEXT,   -- e.g. ICSA-24-123-01, ICSMA-23-045-02
    advisory_title      TEXT,
    vendor              TEXT,
    product             TEXT,
    products_affected   TEXT,   -- free-text version/range info
    cumulative_cvss     REAL,   -- 0.0-10.0, NULL when unavailable
    cvss_severity       TEXT,   -- Critical | High | Medium | Low | NA
    product_distribution TEXT,
    company_headquarters TEXT,
    license             TEXT
);

TABLE advisory_cves (
    id       INTEGER PRIMARY KEY,
    icsad_id INTEGER REFERENCES advisories(icsad_id),
    cve      TEXT    -- e.g. CVE-2024-12345
);

TABLE advisory_cwes (
    id       INTEGER PRIMARY KEY,
    icsad_id INTEGER REFERENCES advisories(icsad_id),
    cwe      TEXT    -- e.g. CWE-79
);

TABLE advisory_sectors (
    id       INTEGER PRIMARY KEY,
    icsad_id INTEGER REFERENCES advisories(icsad_id),
    sector   TEXT    -- e.g. Energy, Water and Wastewater Systems
);

Useful relationships:
- One advisory can have many CVEs, CWEs, and sectors (1-to-many via icsad_id).
- Join advisory_cves/advisory_cwes/advisory_sectors to advisories on icsad_id.

Notes:
- Dates are stored as MM/DD/YYYY text; use substr() or strftime() for filtering.
- The year column is an integer and is the easiest way to filter by year.
- cvss_severity values: Critical, High, Medium, Low, NA.
- Use LIKE for partial text matching on vendor, product, advisory_title.
- Sector names vary; use LIKE '%keyword%' for flexible matching.
"""

SYSTEM_PROMPT = f"""\
You are an expert SQL analyst for CISA ICS (Industrial Control Systems) \
advisory data.  Given a user question, write a single SQLite SELECT query \
that answers the question.

DATABASE SCHEMA
---------------
{SCHEMA_CONTEXT}

RULES
-----
1. Output ONLY a JSON object: {{"sql": "<your query>", "explanation": "<one-line description>"}}.
2. The query MUST be a single SELECT statement.  Never write INSERT, UPDATE, \
DELETE, DROP, ALTER, CREATE, ATTACH, or any mutating statement.
3. Always LIMIT results to 50 rows unless the user explicitly asks for more.
4. When counting or aggregating, use appropriate GROUP BY and ORDER BY.
5. For date filtering prefer the integer `year` column when possible.
6. Use JOINs to advisory_cves / advisory_cwes / advisory_sectors as needed.
7. If the question is ambiguous, make a reasonable assumption and note it in \
the explanation.
8. If you truly cannot answer from this schema, return \
{{"sql": null, "explanation": "reason"}}.
"""

# ---------------------------------------------------------------------------
# LLM provider helpers
# ---------------------------------------------------------------------------

DEFAULT_MODELS = {
    "openai": "gpt-4o",
    "anthropic": "claude-sonnet-4-20250514",
}


def _call_openai(question: str, api_key: str, model: str) -> dict:
    """Call OpenAI Chat Completions and return parsed JSON."""
    try:
        from openai import OpenAI
    except ImportError:
        print("Error: openai package not installed. Run:  pip install openai",
              file=sys.stderr)
        sys.exit(1)

    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=model,
        temperature=0,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
        response_format={"type": "json_object"},
    )
    return json.loads(resp.choices[0].message.content)


def _call_anthropic(question: str, api_key: str, model: str) -> dict:
    """Call Anthropic Messages API and return parsed JSON."""
    try:
        from anthropic import Anthropic
    except ImportError:
        print("Error: anthropic package not installed. Run:  pip install anthropic",
              file=sys.stderr)
        sys.exit(1)

    client = Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=model,
        max_tokens=1024,
        temperature=0,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": question}],
    )
    text = resp.content[0].text
    # Anthropic may wrap JSON in markdown fences — strip them.
    text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
    text = re.sub(r"```\s*$", "", text, flags=re.MULTILINE)
    return json.loads(text.strip())


PROVIDERS = {
    "openai": _call_openai,
    "anthropic": _call_anthropic,
}

# ---------------------------------------------------------------------------
# SQL execution (read-only)
# ---------------------------------------------------------------------------

_DISALLOWED = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH|DETACH|REPLACE|PRAGMA)\b",
    re.IGNORECASE,
)


def execute_query(sql: str) -> tuple[list[str], list[tuple]]:
    """Execute a read-only SQL query and return (columns, rows).

    Raises ValueError on disallowed statements.
    """
    if _DISALLOWED.search(sql):
        raise ValueError(f"Blocked: query contains a disallowed keyword.")

    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        cur = conn.execute(sql)
        columns = [d[0] for d in cur.description] if cur.description else []
        rows = cur.fetchall()
    finally:
        conn.close()
    return columns, rows

# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------


def _format_table(columns: list[str], rows: list[tuple], max_width: int = 40) -> str:
    """Return a simple ASCII table."""
    if not columns:
        return "(no results)"

    str_rows = []
    for row in rows:
        str_rows.append([_trunc(str(v) if v is not None else "", max_width)
                         for v in row])

    col_widths = [len(c) for c in columns]
    for row in str_rows:
        for i, v in enumerate(row):
            col_widths[i] = max(col_widths[i], len(v))

    def fmt_row(vals):
        return " | ".join(v.ljust(w) for v, w in zip(vals, col_widths))

    sep = "-+-".join("-" * w for w in col_widths)
    lines = [fmt_row(columns), sep]
    lines.extend(fmt_row(r) for r in str_rows)
    return "\n".join(lines)


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"

# ---------------------------------------------------------------------------
# Core ask loop
# ---------------------------------------------------------------------------


def ask(question: str, *, provider: str, api_key: str, model: str) -> str:
    """Translate a natural-language question to SQL, execute, and return text."""
    result = PROVIDERS[provider](question, api_key, model)

    sql = result.get("sql")
    explanation = result.get("explanation", "")

    if not sql:
        return f"Could not answer: {explanation}"

    # Validate and run
    try:
        columns, rows = execute_query(sql)
    except (ValueError, sqlite3.Error) as exc:
        return f"SQL error: {exc}\nGenerated query:\n  {sql}"

    table = _format_table(columns, rows)
    parts = []
    if explanation:
        parts.append(explanation)
    parts.append(f"\nSQL:\n  {sql}\n")
    parts.append(f"Results ({len(rows)} row{'s' if len(rows) != 1 else ''}):\n{table}")
    return "\n".join(parts)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Ask natural-language questions about ICS advisories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s --query "Top 10 vendors by advisory count"
              %(prog)s --provider anthropic
              OPENAI_API_KEY=sk-... %(prog)s
        """),
    )
    p.add_argument(
        "--provider", choices=["openai", "anthropic"], default="openai",
        help="LLM provider (default: openai)",
    )
    p.add_argument(
        "--model", default=None,
        help="Override the model name (default: gpt-4o / claude-sonnet-4-20250514)",
    )
    p.add_argument(
        "--api-key", default=None, dest="api_key",
        help="API key (or set OPENAI_API_KEY / ANTHROPIC_API_KEY env var)",
    )
    p.add_argument(
        "--query", "-q", default=None,
        help="Single question (skip interactive mode)",
    )
    p.add_argument(
        "--db", default=None,
        help="Path to SQLite database (default: ics_advisories.db next to this script)",
    )
    return p


def _resolve_api_key(args) -> str:
    key = args.api_key
    if not key:
        env_var = "OPENAI_API_KEY" if args.provider == "openai" else "ANTHROPIC_API_KEY"
        key = os.environ.get(env_var)
    if not key:
        env_var = "OPENAI_API_KEY" if args.provider == "openai" else "ANTHROPIC_API_KEY"
        print(f"Error: No API key. Set {env_var} or pass --api-key.", file=sys.stderr)
        sys.exit(1)
    return key


def main():
    global DB_PATH
    parser = _build_parser()
    args = parser.parse_args()

    if args.db:
        DB_PATH = Path(args.db)

    if not DB_PATH.exists():
        print(f"Error: Database not found at {DB_PATH}", file=sys.stderr)
        print("Run migrate_csv_to_sqlite.py first to create it.", file=sys.stderr)
        sys.exit(1)

    api_key = _resolve_api_key(args)
    model = args.model or DEFAULT_MODELS[args.provider]

    # Single-shot mode
    if args.query:
        print(ask(args.query, provider=args.provider, api_key=api_key, model=model))
        return

    # Interactive REPL
    print(f"ICS Advisory Q&A  (provider={args.provider}, model={model})")
    print("Type your question, or 'exit' / Ctrl-D to quit.\n")

    while True:
        try:
            question = input("Question> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break
        if not question:
            continue
        if question.lower() in ("exit", "quit", "q"):
            print("Bye.")
            break
        print()
        print(ask(question, provider=args.provider, api_key=api_key, model=model))
        print()


if __name__ == "__main__":
    main()
