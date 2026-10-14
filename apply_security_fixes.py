"""Safely annotate the four non-cryptographic MD5 uses flagged by Bandit.

Run from the repository root (or place this helper next to app.py):
    python apply_security_fixes.py          # validate only
    python apply_security_fixes.py --apply  # make the four exact replacements

The script refuses to edit if any expected source expression appears zero or
multiple times. It preserves the original file's line endings and saves a
recoverable backup outside the repository before writing.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import tempfile

REPLACEMENTS = (
    (
        b'hashlib.md5((_a or _n).lower().encode("utf-8", "ignore"))',
        b'hashlib.md5((_a or _n).lower().encode("utf-8", "ignore"), usedforsecurity=False)',
    ),
    (
        b'hashlib.md5(seed.encode("utf-8", "ignore"))',
        b'hashlib.md5(seed.encode("utf-8", "ignore"), usedforsecurity=False)',
    ),
    (
        b'hashlib.md5((_addr or _name).lower().encode("utf-8", "ignore"))',
        b'hashlib.md5((_addr or _name).lower().encode("utf-8", "ignore"), usedforsecurity=False)',
    ),
    (
        b'hashlib.md5(str(case_name).encode("utf-8", "ignore"))',
        b'hashlib.md5(str(case_name).encode("utf-8", "ignore"), usedforsecurity=False)',
    ),
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="apply the validated replacements")
    args = parser.parse_args()

    app_path = Path(__file__).resolve().parent / "app.py"
    if not app_path.is_file():
        parser.error(f"app.py was not found beside this script: {app_path}")

    original = app_path.read_bytes()
    updated = original
    for old, new in REPLACEMENTS:
        count = updated.count(old)
        if count != 1:
            raise SystemExit(
                f"Refusing to edit: expected exactly one match for {old.decode()}, found {count}. "
                "Your app.py differs from the reviewed source; inspect it manually."
            )
        updated = updated.replace(old, new, 1)

    if updated.count(b"usedforsecurity=False") - original.count(b"usedforsecurity=False") != 4:
        raise SystemExit("Refusing to edit: replacement-count verification failed.")

    try:
        compile(updated.decode("utf-8"), str(app_path), "exec")
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise SystemExit(f"Refusing to edit: patched app.py failed syntax validation: {exc}")

    print("Validated 4 exact non-cryptographic MD5 call-site changes; hash outputs remain unchanged.")
    print("Python syntax validation: passed.")
    if not args.apply:
        print("Dry run only. Re-run with --apply to write app.py.")
        return 0

    fd, backup_name = tempfile.mkstemp(prefix="algorithmistic-app-before-md5-fix-", suffix=".bak")
    try:
        with os.fdopen(fd, "wb") as backup:
            backup.write(original)
        temp_path = app_path.with_name(app_path.name + ".security-fix.tmp")
        try:
            temp_path.write_bytes(updated)
            os.replace(temp_path, app_path)
        finally:
            if temp_path.exists():
                temp_path.unlink()
    except Exception:
        if os.path.exists(backup_name):
            os.unlink(backup_name)
        raise

    if app_path.read_bytes() != updated:
        raise SystemExit("File verification failed after write. Restore from backup: " + backup_name)
    print(f"Applied successfully. Backup saved outside the repo: {backup_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
