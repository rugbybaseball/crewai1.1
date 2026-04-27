"""Entry point for the FinServe Problem Management crew.

Usage:
    python main_pm.py

Reads CSVs from data/ (overridable via INCIDENTS_CSV / CMDB_CSV / CHANGES_CSV
env vars), runs the 5-agent sequential crew, and writes Problem Records,
Known Errors, and RFCs into output/.
"""
from src.problem_mgmt.config import (
    CHANGES_CSV,
    CMDB_CSV,
    INCIDENTS_CSV,
    OUTPUT_DIR,
    ensure_output_dir,
)
from src.problem_mgmt.problem_crew import create_problem_crew


def main() -> None:
    print("=" * 80)
    print("FinServe Digital Bank — Agent-Driven Problem Management")
    print("=" * 80)
    print(f"Incidents CSV: {INCIDENTS_CSV}")
    print(f"CMDB CSV:      {CMDB_CSV}")
    print(f"Changes CSV:   {CHANGES_CSV}")

    out_dir = ensure_output_dir()
    print(f"Output dir:    {out_dir}")
    print()

    for csv in (INCIDENTS_CSV, CMDB_CSV, CHANGES_CSV):
        if not csv.exists():
            raise SystemExit(
                f"Missing CSV: {csv}\n"
                "Drop the three FinServe CSVs into data/ (or override via env vars)."
            )

    crew = create_problem_crew()
    result = crew.kickoff()

    print("\n" + "=" * 80)
    print("FINAL PROBLEM MANAGEMENT REPORT")
    print("=" * 80)
    print(result)

    written = sorted(OUTPUT_DIR.glob("*"))
    print("\n" + "=" * 80)
    print(f"Generated {len(written)} files in {OUTPUT_DIR}:")
    for p in written:
        print(f"  - {p.name}")
    print("=" * 80)


if __name__ == "__main__":
    main()
