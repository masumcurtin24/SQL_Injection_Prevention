#!/usr/bin/env python3
"""
Train a text-based file analyzer model to recognize exploit PoCs vs benign docs.

Usage (example):
  python backend/scripts/train_file_poc_model.py \
    --malicious-dirs data/raw/files_for_analysis_training/poc_malicious \
    --benign-dirs data/raw/files_for_analysis_training/benign_docs \
    --out backend/data/models_store/file_analyzer_v1.joblib

Notes:
  - Recursively reads text-like files under the provided directories.
  - Uses TF-IDF (word uni/bi-grams) + RandomForestClassifier.
  - Prints a simple hold-out evaluation.
"""
import argparse
import os
import sys
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score


def collect_texts(dirs: List[str], label: int) -> Tuple[List[str], List[int]]:
    X: List[str] = []
    y: List[int] = []
    for d in dirs:
        if not d:
            continue
        p = Path(d)
        if not p.exists():
            continue
        for path in p.rglob("*"):
            if path.is_file():
                try:
                    # Only load up to 1MB per file to avoid huge memory
                    data = path.read_bytes()[:1_000_000]
                    text = data.decode('utf-8', errors='ignore')
                    if text.strip():
                        X.append(text)
                        y.append(label)
                except Exception:
                    continue
    return X, y


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--malicious-dirs', nargs='+', default=[], help='Directories containing PoC/exploit texts (label=1)')
    ap.add_argument('--benign-dirs', nargs='+', default=[], help='Directories containing benign docs (label=0)')
    ap.add_argument('--out', default=str(Path(__file__).resolve().parents[1] / 'data' / 'models_store' / 'file_analyzer_v1.joblib'))
    args = ap.parse_args()

    X_mal, y_mal = collect_texts(args.malicious_dirs, 1)
    X_ben, y_ben = collect_texts(args.benign_dirs, 0)
    X = X_mal + X_ben
    y = y_mal + y_ben

    if not X:
        print('ERROR: No training data found. Provide --malicious-dirs and --benign-dirs with text files.')
        sys.exit(2)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y if len(set(y)) > 1 else None, random_state=42)

    tfidf = TfidfVectorizer(ngram_range=(1, 2), stop_words='english', min_df=2, max_df=0.95)
    clf = RandomForestClassifier(n_estimators=200, random_state=42, class_weight='balanced', n_jobs=-1)
    pipe = Pipeline([
        ('tfidf', tfidf),
        ('clf', clf),
    ])

    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, digits=4))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, out_path)
    print(f"Saved model to: {out_path}")


if __name__ == '__main__':
    main()

