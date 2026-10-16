from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SQL_CORPUS = PROJECT_ROOT / "backend" / "data" / "corpus" / "sql" / "processed" / "sql_corpus_latest.csv"
DEFAULT_CONTEXT_CORPUS = (
    PROJECT_ROOT / "backend" / "data" / "corpus" / "sql" / "raw" / "sql_request_response_context_latest.csv"
)
ROADMAP_ROOT = PROJECT_ROOT / "backend" / "data" / "benchmarks" / "roadmap"
DEFAULT_REPORT_JSON = ROADMAP_ROOT / "sql_feature_selection_baseline_latest.json"
DEFAULT_REPORT_MD = ROADMAP_ROOT / "sql_feature_selection_baseline_latest.md"
DEFAULT_MODEL_ARTIFACT = PROJECT_ROOT / "backend" / "data" / "models_store" / "sql_feature_selection_baseline.joblib"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _load_sql_corpus(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Missing SQL corpus file: {path}")
    df = pd.read_csv(path, dtype=str, keep_default_na=False).copy()
    if "label" not in df.columns:
        raise ValueError("SQL corpus must include a 'label' column.")
    text_col = "text" if "text" in df.columns else "query"
    if text_col not in df.columns:
        raise ValueError("SQL corpus must include either 'text' or 'query' column.")
    out = pd.DataFrame(
        {
            "text": df[text_col].astype(str),
            "label": df["label"].apply(lambda v: _safe_int(v, default=0)),
            "source": "sql_corpus_latest",
        }
    )
    out = out[out["text"].str.strip() != ""].copy()
    return out.reset_index(drop=True)


def _load_context_corpus(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=["text", "label", "source"])
    df = pd.read_csv(path, dtype=str, keep_default_na=False).copy()
    if "label" not in df.columns:
        return pd.DataFrame(columns=["text", "label", "source"])
    req = df["request_payload_text"] if "request_payload_text" in df.columns else ""
    resp = df["response_context_text"] if "response_context_text" in df.columns else ""
    text = (
        pd.Series(req).astype(str).str.strip()
        + " "
        + pd.Series(resp).astype(str).str.strip()
    ).str.strip()
    out = pd.DataFrame(
        {
            "text": text,
            "label": df["label"].apply(lambda v: _safe_int(v, default=0)),
            "source": "sql_request_response_context",
        }
    )
    out = out[out["text"].str.strip() != ""].copy()
    return out.reset_index(drop=True)


def _compute_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    return {
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "support": int(len(y_true)),
    }


def _top_features(
    vectorizer: TfidfVectorizer,
    selector: SelectKBest,
    classifier: LogisticRegression,
    top_n: int = 30,
) -> List[Dict[str, Any]]:
    names = vectorizer.get_feature_names_out()
    selected_idx = selector.get_support(indices=True)
    selected_names = names[selected_idx]
    coeff = classifier.coef_[0]
    ranked = sorted(
        [
            (selected_names[i], float(coeff[i]), abs(float(coeff[i])))
            for i in range(len(selected_names))
        ],
        key=lambda item: item[2],
        reverse=True,
    )[: max(1, int(top_n))]
    return [
        {"feature": name, "coefficient": round(coef, 6), "importance_abs": round(score, 6)}
        for name, coef, score in ranked
    ]


def _to_markdown(payload: Dict[str, Any]) -> str:
    metrics = payload.get("metrics", {})
    lines = [
        "# SQL Feature-Selection Baseline",
        "",
        f"- Recorded at: `{payload.get('generated_at')}`",
        f"- Training rows: `{payload.get('dataset', {}).get('train_rows')}`",
        f"- Test rows: `{payload.get('dataset', {}).get('test_rows')}`",
        f"- Combined rows: `{payload.get('dataset', {}).get('rows')}`",
        f"- Include context corpus: `{payload.get('dataset', {}).get('include_context')}`",
        "",
        "## Metrics",
        f"- precision={metrics.get('precision')}",
        f"- recall={metrics.get('recall')}",
        f"- f1={metrics.get('f1')}",
        f"- false_positive_rate={metrics.get('false_positive_rate')}",
        "",
        "## Top Selected Features",
    ]
    for item in payload.get("top_features", [])[:20]:
        lines.append(
            f"- {item.get('feature')}: coef={item.get('coefficient')} abs={item.get('importance_abs')}"
        )
    lines.append("")
    return "\n".join(lines)


def run(
    sql_corpus: Path,
    context_corpus: Path,
    include_context: bool,
    k_features: int,
    test_size: float,
    random_state: int,
    report_json: Path,
    report_md: Path,
    model_artifact: Path,
) -> Dict[str, Any]:
    ROADMAP_ROOT.mkdir(parents=True, exist_ok=True)
    sql_df = _load_sql_corpus(sql_corpus)
    frames = [sql_df]
    if include_context:
        ctx = _load_context_corpus(context_corpus)
        if not ctx.empty:
            frames.append(ctx)
    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates(subset=["text", "label"]).reset_index(drop=True)
    if len(df) < 50:
        raise ValueError("Not enough rows for baseline training; expected at least 50 rows.")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"].tolist(),
        df["label"].astype(int).tolist(),
        test_size=float(test_size),
        random_state=int(random_state),
        stratify=df["label"].astype(int).tolist(),
    )

    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=50000,
        lowercase=True,
        strip_accents="unicode",
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    k = min(max(10, int(k_features)), X_train_vec.shape[1])
    selector = SelectKBest(score_func=chi2, k=k)
    X_train_sel = selector.fit_transform(X_train_vec, y_train)
    X_test_sel = selector.transform(X_test_vec)

    clf = LogisticRegression(
        max_iter=1200,
        class_weight="balanced",
        solver="liblinear",
    )
    clf.fit(X_train_sel, y_train)
    y_pred = clf.predict(X_test_sel).tolist()

    metrics = _compute_metrics(y_test, y_pred)
    top_features = _top_features(vectorizer, selector, clf, top_n=40)

    payload = {
        "status": "ok",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "sql_corpus": str(sql_corpus),
            "context_corpus": str(context_corpus),
            "include_context": bool(include_context),
            "rows": int(len(df)),
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
            "label_distribution": {
                "0": int((df["label"] == 0).sum()),
                "1": int((df["label"] == 1).sum()),
            },
            "source_distribution": {
                str(k): int(v) for k, v in df["source"].value_counts().to_dict().items()
            },
        },
        "params": {
            "k_features": int(k),
            "test_size": float(test_size),
            "random_state": int(random_state),
            "vectorizer": "TfidfVectorizer(char_wb, ngram=(3,5), min_df=2)",
            "classifier": "LogisticRegression(liblinear, class_weight=balanced)",
        },
        "metrics": metrics,
        "top_features": top_features,
    }

    model_artifact.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "vectorizer": vectorizer,
            "selector": selector,
            "classifier": clf,
            "metadata": {
                "generated_at": payload["generated_at"],
                "params": payload["params"],
                "metrics": payload["metrics"],
            },
        },
        model_artifact,
    )

    report_json.parent.mkdir(parents=True, exist_ok=True)
    report_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    report_md.write_text(_to_markdown(payload), encoding="utf-8")
    return payload


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Roadmap step: train SQL baseline with chi-square feature selection."
    )
    p.add_argument("--sql-corpus", type=str, default=str(DEFAULT_SQL_CORPUS))
    p.add_argument("--context-corpus", type=str, default=str(DEFAULT_CONTEXT_CORPUS))
    p.add_argument("--include-context", action="store_true")
    p.add_argument("--k-features", type=int, default=3000)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument("--report-json", type=str, default=str(DEFAULT_REPORT_JSON))
    p.add_argument("--report-md", type=str, default=str(DEFAULT_REPORT_MD))
    p.add_argument("--model-artifact", type=str, default=str(DEFAULT_MODEL_ARTIFACT))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    payload = run(
        sql_corpus=Path(args.sql_corpus).resolve(),
        context_corpus=Path(args.context_corpus).resolve(),
        include_context=bool(args.include_context),
        k_features=int(args.k_features),
        test_size=float(args.test_size),
        random_state=int(args.random_state),
        report_json=Path(args.report_json).resolve(),
        report_md=Path(args.report_md).resolve(),
        model_artifact=Path(args.model_artifact).resolve(),
    )
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
