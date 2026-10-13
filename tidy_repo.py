#!/usr/bin/env python3
"""Tidy the Algorithmistic repo layout. Run from the repo root:   python tidy_repo.py [--dry-run]
Moves (with `git mv`, so history is kept):
  root *.sql                        -> supabase/scripts/
  test_global_lock_race.py          -> supabase/scripts/   (interactive script, sits beside race_seed/race_cleanup.sql)
  test_*.py                         -> tests/              (+ tests/__init__.py so imports keep working)
  Privacy.md TERMS.md REVIEW.md *.diff -> docs/
App modules (*.py), README.md, LICENSE, requirements.txt and app.py stay in the root, so `streamlit run app.py` is unchanged.
Then fixes the few path references, refreshes MANIFEST.sha256, and runs the whole suite.  It never commits or pushes."""
import glob, hashlib, os, re, subprocess, sys

DRY = "--dry-run" in sys.argv
OLD = b"os.path.dirname(os.path.abspath(__file__))"
NEW = b"os.path.dirname(os.path.dirname(os.path.abspath(__file__)))"
INIT = '''"""Unit tests. Run from the repository root:  python -m unittest discover -s tests -t .
Puts this folder and the repo root on sys.path so tests can `import test_x` helpers and the app modules."""
import os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)
'''

def sh(*a, check=True):
    return subprocess.run(a, capture_output=True, text=True, check=check)

def die(m): print("ABORT:", m); sys.exit(1)

if not os.path.isfile("app.py") or not os.path.isdir(".git"): die("run this from the repository root (needs app.py and .git)")
if not DRY and sh("git", "status", "--porcelain").stdout.strip(): die("working tree not clean: commit or stash first, so this is easy to undo")
tracked = set(sh("git", "ls-files").stdout.split("\n"))
for f in sorted(tracked):
    if re.match(r"client_secret.*\.json$", os.path.basename(f)):
        print(f"!! SECURITY: {f} is tracked by git. Rotate that secret, then `git rm --cached {f}` (history keeps it until purged).")

moves = []
lock = "test_global_lock_race.py"
for f in sorted(glob.glob("*.sql")): moves.append((f, "supabase/scripts/" + f))
if os.path.exists(lock): moves.append((lock, "supabase/scripts/" + lock))
for f in sorted(glob.glob("test_*.py")):
    if f != lock: moves.append((f, "tests/" + f))
for f in ["Privacy.md", "TERMS.md", "REVIEW.md"] + sorted(glob.glob("*.diff")):
    if os.path.exists(f): moves.append((f, "docs/" + f))
moves = [(s, d) for s, d in moves if s in tracked and not os.path.exists(d)]
print(f"{len(moves)} files to move"); [print(f"  {s} -> {d}") for s, d in moves]
if DRY: sys.exit(0)

for s, d in moves:
    os.makedirs(os.path.dirname(d), exist_ok=True); sh("git", "mv", s, d)
open("tests/__init__.py", "w", newline="\n").write(INIT); sh("git", "add", "tests/__init__.py")

def edit(path, fn):
    b = open(path, "rb").read(); n = fn(b)
    if n != b: open(path, "wb").write(n); sh("git", "add", path); print("  edited", path)

for f in glob.glob("tests/test_*.py"):          # tests now live one level down: repo root is two dirnames up
    edit(f, lambda b: b if NEW in b else b.replace(OLD, NEW))
pi = "tests/test_package_integrity.py"
if os.path.exists(pi):
    edit(pi, lambda b: re.sub(rb'rd\("(20261012_harden_submit_indicators(?:_ROLLBACK)?\.sql)"\)', rb'rd("supabase/scripts/\1")', b))

names = {os.path.basename(s): d for s, d in moves}          # keep docs pointing at the new locations
if os.path.exists("docs/REVIEW.md"):
    def fix(b):
        t = b.decode("utf-8")
        for n, d in sorted(names.items(), key=lambda x: -len(x[0])):
            t = re.sub(r"(?<![\w/.-])" + re.escape(n) + r"(?![\w-])", d, t)
        return t.encode("utf-8")
    edit("docs/REVIEW.md", fix)

if os.path.exists("MANIFEST.sha256"):                         # same files, new paths, fresh hashes
    out = []
    for line in open("MANIFEST.sha256", encoding="utf-8").read().splitlines():
        h, _, p = line.partition("  ")
        p = names.get(p, p)
        out.append(f"{hashlib.sha256(open(p, 'rb').read()).hexdigest()}  {p}" if os.path.exists(p) else line)
    open("MANIFEST.sha256", "w", newline="\n").write("\n".join(out) + "\n"); sh("git", "add", "MANIFEST.sha256")

print("\nRunning tests: python -m unittest discover -s tests -t .")
r = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-t", "."], capture_output=True, text=True)
print("\n".join(r.stderr.strip().splitlines()[-4:]))
print("\nTests PASSED. Review `git status`, then commit." if r.returncode == 0 else "\nTests FAILED: nothing is committed. Undo with `git reset --hard` (tree was clean before).")
sys.exit(r.returncode)
