"""
CLI untuk owasp-audit-agent.

Pemakaian:
    owasp-audit path/ke/file.py
    owasp-audit file.py --json
    owasp-audit --list-checkers
"""
import argparse
import json
import sys

from agent.registry import registry
from agent.graph import audit_code


def _cmd_list_checkers() -> int:
    registry.discover()
    checkers = registry.list_registered()
    print(f"{len(checkers)} checker terdaftar:")
    for line in sorted(checkers):
        print(f"  - {line}")
    return 0


def _cmd_audit(path: str, as_json: bool) -> int:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            code = fh.read()
    except OSError as exc:
        print(f"Gagal membaca file: {exc}", file=sys.stderr)
        return 2

    result = audit_code(code, filename=path)
    findings = result.get("findings", [])

    if as_json:
        payload = {
            "filename": path,
            "summary": result.get("summary", ""),
            "escalated": result.get("escalated", False),
            "findings": [f.model_dump(mode="json") for f in findings],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 1 if findings else 0

    if not findings:
        print(f"✓ Tidak ada temuan pada {path}.")
        return 0

    print(f"Ditemukan {len(findings)} isu pada {path}:\n")
    for f in findings:
        loc = f" (baris {f.line_number})" if f.line_number else ""
        print(f"  [{f.severity.value}] {f.owasp_category.value}{loc}")
        print(f"      {f.title}")
    if result.get("escalated"):
        print(f"\n⚠  {result.get('escalation_message', 'Eskalasi keamanan.')}")
    print(f"\nRingkasan:\n{result.get('summary', '')}")
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="owasp-audit",
        description="Audit keamanan kode Python berbasis OWASP Top 10 (2025).",
    )
    parser.add_argument("path", nargs="?", help="File Python yang akan diaudit.")
    parser.add_argument("--json", action="store_true", help="Keluarkan hasil sebagai JSON.")
    parser.add_argument("--list-checkers", action="store_true", help="Tampilkan checker terdaftar lalu keluar.")
    args = parser.parse_args(argv)

    if args.list_checkers:
        return _cmd_list_checkers()
    if not args.path:
        parser.error("berikan path file, atau gunakan --list-checkers")
    return _cmd_audit(args.path, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
