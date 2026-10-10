"""Leakage and quality audit helpers for the phishing classifier (no I/O side effects).

Used by classifier.train()/train_with_feedback() as safeguards and by the tests/rebuild tool to
measure generalisation on data the synthetic generator did not write. Brand names are only used to
AUDIT label balance here - they never influence a verdict.
"""
import os
import re

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

import config as C

INDEPENDENT_EVAL_CSV = os.path.join(C.BASE_DIR, "fixtures", "independent_eval.csv")
_URL = re.compile(r"(?:https?://|www\.)\S+", re.I)


def normalize_text(text):
    """Template key: lower-case, URLs -> 'url', digits -> '0', punctuation/whitespace collapsed.
    Two emails with the same key are the same wording with different slot-fills."""
    t = _URL.sub(" url ", str(text or "").lower())
    t = re.sub(r"\d+", "0", t)
    return re.sub(r"[^a-z0]+", " ", t).strip()


_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL_FULL = re.compile(r"((?:https?://)?[^\s/?#<>\"']+)[/?#]\S*", re.I)


def sanitize_for_training(text):
    """Privacy: remove personal identifiers before text enters a training set. Email addresses become
    user@example.com; URLs keep scheme+host but lose path/query/fragment (personalised tokens, IDs)."""
    t = _EMAIL.sub("user@example.com", str(text or ""))
    return re.sub(r"(?i)(https?://[^\s/?#<>\"']+)[/?#]\S*", r"\1/", t)


def brand_tokens():
    """Brand words used for the balance audit: first word of each generator brand + config brands."""
    names = set()
    try:
        import gen_data
        names |= {b.split()[0].lower() for b in gen_data.PHISH_BRANDS}
    except Exception:
        pass
    names |= {str(b).lower() for b in getattr(C, "KNOWN_BRANDS", [])}
    return sorted(n for n in names if len(n) >= 3)


def _has(text, brand):
    return re.search(r"(?<![a-z0-9])" + re.escape(brand) + r"(?![a-z0-9])", str(text).lower()) is not None


def brand_label_report(df, min_count=5, min_minority_share=0.05):
    """Per-brand class counts and the brands whose label is (almost) determined by the name alone.

    A brand is one-sided when it occurs >= min_count times and one class holds < min_minority_share of
    those rows - the model can then learn "brand name => label" instead of reading context.
    """
    counts, one_sided = {}, []
    for brand in brand_tokens():
        mask = df["text"].map(lambda t, b=brand: _has(t, b))
        n_phish = int((df.loc[mask, "label"] == "phish").sum())
        n_legit = int((df.loc[mask, "label"] == "legit").sum())
        if n_phish + n_legit == 0:
            continue
        counts[brand] = {"phish": n_phish, "legit": n_legit}
        total = n_phish + n_legit
        if total >= min_count and min(n_phish, n_legit) / total < min_minority_share:
            one_sided.append(brand)
    return {"counts": counts, "one_sided": sorted(one_sided)}


def metrics(y_true, y_pred):
    """Phishing is the positive class. Returns precision, recall, accuracy and raw counts."""
    y_true, y_pred = list(y_true), list(y_pred)
    tp = sum(t == "phish" and p == "phish" for t, p in zip(y_true, y_pred))
    fp = sum(t == "legit" and p == "phish" for t, p in zip(y_true, y_pred))
    fn = sum(t == "phish" and p == "legit" for t, p in zip(y_true, y_pred))
    tn = sum(t == "legit" and p == "legit" for t, p in zip(y_true, y_pred))
    n = len(y_true)
    return {"n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
            "accuracy": (tp + tn) / n if n else 0.0}


def evaluate(pipe, df):
    return metrics(df["label"], pipe.predict(df["text"]))


def load_independent_eval(path=None):
    """Independently authored examples (not produced by gen_data templates). None if absent."""
    path = path or INDEPENDENT_EVAL_CSV
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path).dropna(subset=["text", "label"])
    return df if len(df) else None


def leakage_report(train_df, test_df):
    """How many test rows share a template key with a training row (duplicate / template leakage)."""
    seen = {normalize_text(t) for t in train_df["text"]}
    shared = sum(normalize_text(t) in seen for t in test_df["text"])
    return {"test_rows": len(test_df), "test_rows_sharing_template_with_train": int(shared)}


def drop_feedback_leaks(feedback_df, base_test_df):
    """Collapse near-duplicate feedback (one example per template key) and drop anything that matches a
    held-out evaluation row, so duplicates can neither dominate training nor inflate validation.
    Returns (clean_df, {"duplicates": n, "overlap_with_holdout": n})."""
    holdout = {normalize_text(t) for t in base_test_df["text"]}
    keys = feedback_df["text"].map(normalize_text)
    dup = keys.duplicated(keep="first")
    overlap = keys.isin(holdout)
    clean = feedback_df[~dup & ~overlap]
    return clean.reset_index(drop=True), {"duplicates": int(dup.sum()),
                                          "overlap_with_holdout": int((~dup & overlap).sum())}


def brand_holdout_eval(df, build, min_rows=8):
    """Train WITHOUT any row that names brand B, test only on rows that name B; pooled over brands.
    Measures whether the model still works when it has never seen the brand's wording."""
    y_true, y_pred, per_brand = [], [], {}
    for brand in brand_tokens():
        mask = df["text"].map(lambda t, b=brand: _has(t, b))
        test, train = df[mask], df[~mask]
        if len(test) < min_rows or test["label"].nunique() < 2 or train["label"].nunique() < 2:
            continue
        pipe = build()
        pipe.fit(train["text"], train["label"])
        pred = pipe.predict(test["text"])
        per_brand[brand] = metrics(test["label"], pred)
        y_true += list(test["label"])
        y_pred += list(pred)
    return {"pooled": metrics(y_true, y_pred), "per_brand": per_brand}


def template_group_eval(df, build, test_size=0.25, seed=42):
    """Template-separated split (whole templates held out), same idea as classifier.train()."""
    groups = df["template_id"] if "template_id" in df.columns else df["text"].map(normalize_text)
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
                  .split(df["text"], df["label"], groups=groups))
    pipe = build()
    pipe.fit(df.iloc[tr]["text"], df.iloc[tr]["label"])
    return metrics(df.iloc[te]["label"], pipe.predict(df.iloc[te]["text"]))
