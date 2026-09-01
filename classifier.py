"""Module 1: the ML phishing classifier.

TF-IDF (word 1-2 grams) + Logistic Regression. Deliberately simple because:
  - it trains in under a second, so first launch is not a wait,
  - the coefficients are directly readable, which gives us free EXPLAINABILITY
    ("flagged because of: verify, suspended, click here"),
  - no GPU, no downloads, nothing to break on stage.

The model is trained once and cached to data/model.joblib.

Standalone:  python classifier.py
"""
import os
import re
import sqlite3

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

import config as C
import gen_data

FEEDBACK_DB = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "threat_memory.db"
)

TOKEN_RE = re.compile(r"[a-z][a-z'-]+")


def _build():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2), min_df=2, sublinear_tf=True,
            strip_accents="unicode", lowercase=True, stop_words="english",
        )),
        ("clf", LogisticRegression(max_iter=1000, C=4.0, random_state=42)),
    ])

def _load_feedback_samples():
    """
Load analyst-verified samples collected by the application.

    Returns a DataFrame with:
        text
        label
    """

    if not os.path.exists(FEEDBACK_DB):
        return pd.DataFrame(columns=["text", "label"])

    try:
        conn = sqlite3.connect(FEEDBACK_DB)

        df = pd.read_sql_query(
            """
            SELECT text, label
            FROM feedback_samples
            WHERE text IS NOT NULL
              AND TRIM(text) != ''
              AND label IN ('phish', 'legit')
            """,
            conn
        )

        conn.close()

        if df.empty:
            return pd.DataFrame(columns=["text", "label"])

        return df.drop_duplicates(subset=["text"])

    except Exception:
        return pd.DataFrame(columns=["text", "label"])


def train(save=True):
    """Train on data/emails.csv (generating it first if missing).

    Scoring uses a GROUPED split: entire templates are held out, so the test set
    contains wording the model has never seen. A plain random split shares
    templates between train and test and reports a meaningless 100%.

    Returns (pipeline, metrics_dict).
    """
    if not os.path.exists(C.EMAILS_CSV):
        gen_data.generate()

    df = pd.read_csv(C.EMAILS_CSV).dropna(subset=["text", "label"])
    if "template_id" not in df.columns:       # tolerate an older CSV
        df["template_id"] = df.index.astype(str)

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(
        splitter.split(df["text"], df["label"], groups=df["template_id"])
    )
    train_df, test_df = df.iloc[train_idx], df.iloc[test_idx]

    pipe = _build()
    pipe.fit(train_df["text"], train_df["label"])
    predictions = pipe.predict(test_df["text"])

    metrics = {
        "n_train": len(train_df),
        "n_test": len(test_df),
        "n_templates_train": train_df["template_id"].nunique(),
        "n_templates_test": test_df["template_id"].nunique(),
        "accuracy": float(accuracy_score(test_df["label"], predictions)),
        "report": classification_report(test_df["label"], predictions,
                                        zero_division=0),
        "confusion": confusion_matrix(test_df["label"], predictions,
                                      labels=["legit", "phish"]).tolist(),
        "split": "grouped by template (unseen wording)",
    }

    # The shipped model is then refit on ALL rows so it benefits from every
    # template; the score above is the honest estimate of how it generalises.
    final = _build()
    final.fit(df["text"], df["label"])
    if save:
        os.makedirs(os.path.dirname(C.MODEL_PATH), exist_ok=True)
        joblib.dump(final, C.MODEL_PATH)
        try:
            joblib.dump(metrics, C.MODEL_PATH + ".metrics")
        except Exception:
            pass
    return final, metrics

def train_with_feedback(min_samples=20, save=True):
    """
    Train an adaptive candidate using verified feedback.

    The candidate is accepted only when its validation accuracy is
    at least as good as the baseline model.
    """

    feedback_df = _load_feedback_samples()

    if len(feedback_df) < min_samples:
        return None, {
            "status": "waiting",
            "feedback_samples": len(feedback_df),
            "required_samples": min_samples,
        }

    if feedback_df["label"].nunique() < 2:
        return None, {
            "status": "waiting_for_both_classes",
            "feedback_samples": len(feedback_df),
            "required_samples": min_samples,
        }

    # Load the original dataset.
    if not os.path.exists(C.EMAILS_CSV):
        gen_data.generate()

    base_df = pd.read_csv(
        C.EMAILS_CSV
    ).dropna(
        subset=["text", "label"]
    ).copy()

    if "template_id" not in base_df.columns:
        base_df["template_id"] = (
            base_df.index.astype(str)
        )

    # Keep complete templates together.
    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.25,
        random_state=42,
    )

    train_idx, test_idx = next(
        splitter.split(
            base_df["text"],
            base_df["label"],
            groups=base_df["template_id"],
        )
    )

    base_train = base_df.iloc[train_idx]
    base_test = base_df.iloc[test_idx]

    # --------------------------------------------------------------
    # 1. Baseline model
    # --------------------------------------------------------------
    baseline_model = _build()

    baseline_model.fit(
        base_train["text"],
        base_train["label"],
    )

    baseline_predictions = baseline_model.predict(
        base_test["text"]
    )

    baseline_accuracy = float(
        accuracy_score(
            base_test["label"],
            baseline_predictions,
        )
    )

    # --------------------------------------------------------------
    # 2. Candidate adaptive model
    # --------------------------------------------------------------
    combined_train = pd.concat(
        [
            base_train[["text", "label"]],
            feedback_df[["text", "label"]],
        ],
        ignore_index=True,
    )

    # Same email remains one training example.
    combined_train = combined_train.drop_duplicates(
        subset=["text"]
    ).reset_index(drop=True)

    candidate_model = _build()

    candidate_model.fit(
        combined_train["text"],
        combined_train["label"],
    )

    candidate_predictions = candidate_model.predict(
        base_test["text"]
    )

    candidate_accuracy = float(
        accuracy_score(
            base_test["label"],
            candidate_predictions,
        )
    )

    # --------------------------------------------------------------
    # 3. Safety gate
    # --------------------------------------------------------------
    if candidate_accuracy < baseline_accuracy:

        return None, {
            "status": "rejected",
            "feedback_samples": len(feedback_df),
            "baseline_accuracy": baseline_accuracy,
            "candidate_accuracy": candidate_accuracy,
            "message": (
                "Adaptive model rejected because validation "
                "accuracy decreased."
            ),
        }

    # --------------------------------------------------------------
    # 4. Accept and save
    # --------------------------------------------------------------
    if save:
        os.makedirs(
            os.path.dirname(C.MODEL_PATH),
            exist_ok=True,
        )

        joblib.dump(
            candidate_model,
            C.MODEL_PATH,
        )

        adaptive_info = {
            "status": "trained",
            "feedback_samples": len(feedback_df),
            "total_samples": len(combined_train),
            "model_type": "adaptive_feedback",
            "baseline_accuracy": baseline_accuracy,
            "candidate_accuracy": candidate_accuracy,
        }

        try:
            joblib.dump(
                adaptive_info,
                C.MODEL_PATH + ".adaptive",
            )
        except Exception:
            pass

    return candidate_model, {
        "status": "trained",
        "feedback_samples": len(feedback_df),
        "total_samples": len(combined_train),
        "baseline_accuracy": baseline_accuracy,
        "candidate_accuracy": candidate_accuracy,
    }
    """
    Train a candidate adaptive model and accept it only when it is
    not worse than the baseline on a fixed holdout set.
    """

    feedback_df = _load_feedback_samples()

    if len(feedback_df) < min_samples:
        return None, {
            "status": "waiting",
            "feedback_samples": len(feedback_df),
            "required_samples": min_samples,
        }

    if feedback_df["label"].nunique() < 2:
        return None, {
            "status": "waiting_for_both_classes",
            "feedback_samples": len(feedback_df),
            "required_samples": min_samples,
        }

    # Load original training corpus.
    if not os.path.exists(C.EMAILS_CSV):
        gen_data.generate()

    base_df = pd.read_csv(C.EMAILS_CSV).dropna(
        subset=["text", "label"]
    ).copy()

    if "template_id" not in base_df.columns:
        base_df["template_id"] = base_df.index.astype(str)

    # Fixed grouped holdout so whole templates stay together.
    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.25,
        random_state=42
    )

    train_idx, test_idx = next(
        splitter.split(
            base_df["text"],
            base_df["label"],
            groups=base_df["template_id"]
        )
    )

    base_train = base_df.iloc[train_idx]
    base_test = base_df.iloc[test_idx]

    # -------------------------
    # Baseline model
    # -------------------------
    baseline_model = _build()

    baseline_model.fit(
        base_train["text"],
        base_train["label"]
    )

    baseline_predictions = baseline_model.predict(
        base_test["text"]
    )

    baseline_accuracy = float(
        accuracy_score(
            base_test["label"],
            baseline_predictions
        )
    )

    # -------------------------
    # Candidate adaptive model
    # -------------------------
    combined_train = pd.concat(
        [
            base_train[["text", "label"]],
            feedback_df[["text", "label"]],
        ],
        ignore_index=True
    )

    # Same email should never be counted repeatedly.
    combined_train = combined_train.drop_duplicates(
        subset=["text"]
    ).reset_index(drop=True)

    candidate_model = _build()

    candidate_model.fit(
        combined_train["text"],
        combined_train["label"]
    )

    candidate_predictions = candidate_model.predict(
        base_test["text"]
    )

    candidate_accuracy = float(
        accuracy_score(
            base_test["label"],
            candidate_predictions
        )
    )

    # -------------------------
    # Safety gate
    # -------------------------
    accepted = candidate_accuracy >= baseline_accuracy

    if not accepted:
        return None, {
            "status": "rejected",
            "feedback_samples": len(feedback_df),
            "baseline_accuracy": baseline_accuracy,
            "candidate_accuracy": candidate_accuracy,
            "message": "Adaptive model rejected because validation accuracy decreased.",
        }

    if save:
        os.makedirs(
            os.path.dirname(C.MODEL_PATH),
            exist_ok=True
        )

        # Save only after passing validation.
        joblib.dump(
            candidate_model,
            C.MODEL_PATH
        )

        adaptive_info = {
            "status": "trained",
            "feedback_samples": len(feedback_df),
            "total_samples": len(combined_train),
            "model_type": "adaptive_feedback",
            "baseline_accuracy": baseline_accuracy,
            "candidate_accuracy": candidate_accuracy,
        }

        try:
            joblib.dump(
                adaptive_info,
                C.MODEL_PATH + ".adaptive"
            )
        except Exception:
            pass

    return candidate_model, {
        "status": "trained",
        "feedback_samples": len(feedback_df),
        "total_samples": len(combined_train),
        "baseline_accuracy": baseline_accuracy,
        "candidate_accuracy": candidate_accuracy,
    }


def get_adaptive_status():
    """Return information about the last adaptive training run."""

    adaptive_file = C.MODEL_PATH + ".adaptive"

    if not os.path.exists(adaptive_file):
        return {
            "status": "base",
            "feedback_samples": 0,
            "total_samples": 0,
        }

    try:
        return joblib.load(adaptive_file)
    except Exception:
        return {
            "status": "base",
            "feedback_samples": 0,
            "total_samples": 0,
        }

def get_feedback_count():
    """Return the number of unique verified feedback samples."""

    feedback_df = _load_feedback_samples()

    return len(feedback_df)


def maybe_retrain_from_feedback():
    """
    Retrain only when there are at least 20 verified samples and
    at least 10 new samples have been collected since the last
    adaptive training run.
    """

    feedback_df = _load_feedback_samples()
    feedback_count = len(feedback_df)

    if feedback_count < 20:
        return {
            "status": "waiting",
            "feedback_samples": feedback_count,
            "message": "Need at least 20 verified samples."
        }

    previous = get_adaptive_status()
    previous_count = int(previous.get("feedback_samples", 0))

    if feedback_count - previous_count < 10:
        return {
            "status": "waiting",
            "feedback_samples": feedback_count,
            "message": "Waiting for 10 additional verified samples."
        }

    model, result = train_with_feedback(
        min_samples=20,
        save=True
    )

    return result

def cached_metrics():
    """Metrics saved alongside the model, or None. Avoids retraining for the UI."""
    try:
        return joblib.load(C.MODEL_PATH + ".metrics")
    except Exception:
        return None


def load_or_train():
    """Load the cached model, retraining if it is missing or unreadable."""
    if os.path.exists(C.MODEL_PATH):
        try:
            return joblib.load(C.MODEL_PATH)
        except Exception:
            pass
    return train()[0]


def _phish_index(pipe):
    """Column of 'phish' in predict_proba - never assume it is index 1."""
    classes = list(pipe.named_steps["clf"].classes_)
    return classes.index("phish") if "phish" in classes else len(classes) - 1


def explain(pipe, text, top_n=8):
    """Words present in this email that push the model toward 'phish'.

    Logistic-regression coefficients are per-feature log-odds, so we simply
    rank the positive-weight features that actually occur in this text.
    """
    try:
        tfidf = pipe.named_steps["tfidf"]
        clf = pipe.named_steps["clf"]
        vec = tfidf.transform([text])
        names = tfidf.get_feature_names_out()
        coefs = clf.coef_[0]
        # Orient coefficients so positive always means "more phishing".
        if _phish_index(pipe) == 0:
            coefs = -coefs

        scored = []
        for idx in vec.nonzero()[1]:
            contribution = coefs[idx] * vec[0, idx]
            if contribution > 0:
                scored.append((names[idx], float(contribution)))
        scored.sort(key=lambda kv: kv[1], reverse=True)
        return scored[:top_n]
    except Exception:
        return []


def predict(pipe, text):
    """Returns (prob_phish, label, top_terms). Safe on empty input."""
    text = (text or "").strip()
    if not text:
        return 0.0, "legit", []
    prob = float(pipe.predict_proba([text])[0][_phish_index(pipe)])
    label = "phish" if prob >= 0.5 else "legit"
    return prob, label, explain(pipe, text)


if __name__ == "__main__":
    pipe, metrics = train()
    print("split: {}".format(metrics["split"]))
    print("train: {} rows / {} templates".format(
        metrics["n_train"], metrics["n_templates_train"]))
    print("test : {} rows / {} templates (wording never seen in training)".format(
        metrics["n_test"], metrics["n_templates_test"]))
    print("\nheld-out accuracy: {:.1%}\n".format(metrics["accuracy"]))
    print(metrics["report"])
    print("confusion [rows=actual legit,phish | cols=pred legit,phish]:")
    for row in metrics["confusion"]:
        print("   ", row)

    demos = [
        ("loud phish",
         "PayPal: your account has been suspended. Click here to verify your "
         "identity immediately. http://bit.ly/2xKp9Lq"),
        ("ordinary legit",
         "Hi Priya, attached are the notes from yesterday's review meeting. "
         "Let me know if anything needs correcting."),
        ("HARD negative (legit, scary words)",
         "Scheduled notice from IT: your network password will expire in 14 "
         "days. Please change it using Ctrl+Alt+Del on your work machine. We "
         "will never email you a link to reset it."),
    ]
    print()
    for name, text in demos:
        prob, label, terms = predict(pipe, text)
        print("{:38} {:5.1%} phishing -> {}".format(name, prob, label))
