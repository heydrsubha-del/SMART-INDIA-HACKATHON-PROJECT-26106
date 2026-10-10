"""Safe, reversible rebuild of the phishing corpus + model.   python rebuild_model.py [--apply] [--force]

Default is a DRY RUN: nothing under data/ is modified. The new corpus/model are built in a temporary
directory, compared with the current ones on independently authored examples, and only promoted with
--apply (after a timestamped backup). Rows in data/emails.csv that the generator did not write (possible
user data) are inspected, reported and carried over, never discarded. threat_memory.db is only read.
"""
import os
import shutil
import sqlite3
import sys
import tempfile
import time

import joblib
import pandas as pd

import classifier as K
import config as C
import gen_data as G
import model_audit as A

GEN_PREFIXES = ("phish_loud_", "bec_", "phish_soft_", "legit_plain_", "legit_hard_", "legit_brand_")
SIDE_FILES = (".metrics", ".adaptive")


def _feedback_count():
    """Verified analyst samples in the local DB (read-only; these live in the DB, not in emails.csv)."""
    try:
        conn = sqlite3.connect("file:{}?mode=ro".format(K.FEEDBACK_DB), uri=True)
        try:
            return conn.execute("SELECT COUNT(*) FROM feedback_samples").fetchone()[0]
        finally:
            conn.close()
    except Exception:
        return 0


def _inspect_corpus(path):
    """(dataframe, n_generator_rows, non_generator_rows_df). Missing template_id => not generator-made."""
    df = pd.read_csv(path).dropna(subset=["text", "label"])
    tid = df["template_id"].astype(str) if "template_id" in df.columns else pd.Series([""] * len(df))
    gen = tid.str.startswith(GEN_PREFIXES).values
    return df, int(gen.sum()), df[~gen]


def _evaluate(model, ind):
    return A.evaluate(model, ind) if (model is not None and ind is not None) else None


def run(apply=False, force=False, out=print):
    ind = A.load_independent_eval()
    old_model = None
    if os.path.exists(C.MODEL_PATH):
        try:
            old_model = joblib.load(C.MODEL_PATH)
        except Exception:
            pass

    keep = pd.DataFrame(columns=["text", "label", "template_id"])
    if os.path.exists(C.EMAILS_CSV):
        _, n_gen, keep = _inspect_corpus(C.EMAILS_CSV)
        out("current corpus: {} generator rows, {} NON-generator rows (kept)".format(n_gen, len(keep)))
    else:
        out("no current corpus (a fresh one will be generated)")
    out("verified analyst samples in threat_memory.db (read-only, not part of the corpus): {}".format(_feedback_count()))

    tmp = tempfile.mkdtemp(prefix="algo_rebuild_")
    saved = (C.EMAILS_CSV, C.MODEL_PATH)
    try:
        new_csv, new_model_path = os.path.join(tmp, "emails.csv"), os.path.join(tmp, "model.joblib")
        G.generate(path=new_csv)
        if len(keep):
            fresh = pd.read_csv(new_csv)
            pd.concat([fresh, keep[fresh.columns.intersection(keep.columns)]], ignore_index=True) \
                .drop_duplicates(subset=["text"]).to_csv(new_csv, index=False)
        C.EMAILS_CSV, C.MODEL_PATH = new_csv, new_model_path
        new_model, m = K.train(save=True)
    finally:
        C.EMAILS_CSV, C.MODEL_PATH = saved

    old_m, new_m = _evaluate(old_model, ind), _evaluate(new_model, ind)
    for name, r in (("current model", old_m), ("rebuilt model", new_m)):
        out("{:14} independent set: {}".format(name, "n/a" if r is None else
            "P={precision:.2f} R={recall:.2f} acc={accuracy:.2f} FP={fp} FN={fn}".format(**r)))
    out("rebuilt (template-held-out) accuracy {:.1%}; template leakage rows: {}; one-sided brands: {}".format(
        m["accuracy"], m["leakage"]["test_rows_sharing_template_with_train"], m["brand_one_sided"] or "none"))

    if not apply:
        out("DRY RUN - nothing under data/ was changed. Re-run with --apply to promote (backup first).")
        return {"applied": False, "tmp": tmp, "old": old_m, "new": new_m}
    if old_m and new_m and new_m["accuracy"] + 0.02 < old_m["accuracy"] and not force:
        out("REFUSED: rebuilt model is worse on the independent set (use --force to override).")
        return {"applied": False, "tmp": tmp, "old": old_m, "new": new_m}

    backup = os.path.join(os.path.dirname(C.EMAILS_CSV) or ".", "backup_" + time.strftime("%Y%m%d_%H%M%S"))
    os.makedirs(backup)
    for src in [C.EMAILS_CSV, C.MODEL_PATH] + [C.MODEL_PATH + s for s in SIDE_FILES]:
        if os.path.exists(src):
            shutil.copy2(src, backup)
    os.makedirs(os.path.dirname(C.MODEL_PATH), exist_ok=True)
    shutil.copy2(new_csv, C.EMAILS_CSV)
    shutil.copy2(new_model_path, C.MODEL_PATH)
    if os.path.exists(new_model_path + ".metrics"):
        shutil.copy2(new_model_path + ".metrics", C.MODEL_PATH + ".metrics")
    adaptive = C.MODEL_PATH + ".adaptive"
    if os.path.exists(adaptive):          # old adaptive model was fitted to the OLD corpus: reset to base
        os.remove(adaptive)
    out("APPLIED. Backup of previous files: {}".format(backup))
    return {"applied": True, "backup": backup, "tmp": tmp, "old": old_m, "new": new_m}


if __name__ == "__main__":
    run(apply="--apply" in sys.argv, force="--force" in sys.argv)
