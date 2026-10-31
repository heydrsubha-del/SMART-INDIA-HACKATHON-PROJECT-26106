"""THROWAWAY wrapper: run the REAL Streamlit app (app.py) with ONE fault injected, to check the real UI by eye.

    cd /path/to/disposable/copy/of/the/repo        # a COPY without live credentials is strongly recommended
    FAULT_REPO=. FAULT_SCENARIO=detector_failure streamlit run /path/to/fault_injection_app.py

FAULT_SCENARIO is one of: detector_failure | truncated | malformed_url_score | missing_url_risk | genuine_sextortion |
clean_control (see README.md for what to expect). Faults are injected process-wide for the life of this Streamlit server,
so EVERY email you analyse (upload samples/sextortion_private_photo.eml or any .eml) shows the effect.

Isolation: threat memory goes to a temp directory; the ML model is not loaded or trained (fixed probability injected);
outbound HTTP via `requests` is blocked; community intel is forced off. Raw sockets are NOT blocked here (the Streamlit
server needs them). The app itself may still write session files under the OS temp dir - run `git status` afterwards.
This script never reads .streamlit/secrets.toml. NOT verified against real Streamlit in the environment it was written in.
"""
import contextlib
import os
import runpy
import sys
import tempfile

sys.dont_write_bytecode = True
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
import fault_injection_check as fic            # noqa: E402  (shared isolation + fault code, unit-run by the CLI check)


def _setup():
    # Streamlit re-executes THIS file in a fresh namespace on every interaction, so the "already applied" marker must
    # live in a module that stays cached in sys.modules (fic), not in this file's globals.
    if getattr(fic, "APPLIED", None) is not None:
        return
    repo = os.path.abspath(os.environ.get("FAULT_REPO", "."))
    scenario = os.environ.get("FAULT_SCENARIO", "detector_failure")
    if scenario not in fic.SCENARIOS:
        raise SystemExit("FAULT_SCENARIO must be one of: " + ", ".join(fic.SCENARIOS))
    m = fic.load_repo(repo)
    stack = contextlib.ExitStack()
    tmp = tempfile.mkdtemp(prefix="fault_injection_app_")
    fic.isolate(m, stack, tmp, block_sockets=False)
    fic.apply_fault(m, stack, scenario, mode="app")
    fic.APPLIED = (scenario, repo, tmp, stack)
    print("[fault-injection] scenario=%s repo=%s temp=%s" % (scenario, repo, tmp), file=sys.stderr)


_setup()
runpy.run_path(os.path.join(os.path.abspath(os.environ.get("FAULT_REPO", ".")), "app.py"), run_name="__main__")
