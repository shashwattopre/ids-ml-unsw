import argparse
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, StratifiedKFold, ParameterSampler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.class_weight import compute_class_weight
from sklearn.base import clone
from tqdm import tqdm

RANDOM_STATE = 42

# Selected features from NF-UNSW-NB15-v3 dataset
SELECTED_FEATURES = [
    "PROTOCOL", "L4_SRC_PORT", "L4_DST_PORT",
    "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS", "TCP_FLAGS"
]
TARGET = "Label"  # dataset has binary label (Normal/Attack)

CATEGORICAL = ["PROTOCOL", "TCP_FLAGS"]
NUMERIC = [c for c in SELECTED_FEATURES if c not in CATEGORICAL]


def load_dataset(path: str, max_samples: int | None = None) -> pd.DataFrame:
    df = pd.read_csv(path)

    # Ensure binary target
    df[TARGET] = df[TARGET].astype(str).str.lower().map(
        lambda x: 1 if x in {"attack", "anomaly", "malicious", "1", "true"} else 0
    )

    if max_samples is not None and len(df) > max_samples:
        df = df.sample(n=max_samples, random_state=RANDOM_STATE)

    return df.dropna(subset=SELECTED_FEATURES + [TARGET])


def build_pipeline() -> Pipeline:
    pre = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL),
        ("num", StandardScaler(), NUMERIC),
    ])
    clf_rf = RandomForestClassifier(
        n_estimators=300, n_jobs=-1, random_state=RANDOM_STATE
    )
    return Pipeline([("pre", pre), ("clf", clf_rf)])


def tune_model(pipe: Pipeline, X, y, n_iter: int = 10):
    """Custom hyperparameter tuning with progress bar."""
    param_dist = {
        "clf__n_estimators": [200, 300, 400, 600],
        "clf__max_depth": [None, 10, 20, 30],
        "clf__min_samples_split": [2, 5, 10],
        "clf__min_samples_leaf": [1, 2, 4],
        "clf__max_features": ["sqrt", "log2", None]
    }

    param_list = list(ParameterSampler(param_dist, n_iter=n_iter, random_state=RANDOM_STATE))
    best_score, best_model, best_params = -1, None, None

    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)

    for params in tqdm(param_list, desc="Tuning progress"):
        pipe.set_params(**params)
        scores = []
        for train_idx, val_idx in cv.split(X, y):
            X_train, X_val = X.iloc[train_idx], X.iloc[val_idx]
            y_train, y_val = y.iloc[train_idx], y.iloc[val_idx]

            pipe.fit(X_train, y_train)
            scores.append(pipe.score(X_val, y_val))

        mean_score = np.mean(scores)
        if mean_score > best_score:
            best_score = mean_score
            best_model = clone(pipe)
            best_params = params

    print(f"\n✅ Best tuning params: {best_params}, score={best_score:.4f}")
    return best_model, best_params


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--model-out", default="model/pipeline.joblib")
    ap.add_argument("--schema-out", default="model/feature_schema.json")
    ap.add_argument("--fast", action="store_true", help="Train quickly on subset (default 100k)")
    ap.add_argument("--full", action="store_true", help="Train on full dataset")
    ap.add_argument("--tuned", action="store_true", help="Enable hyperparameter tuning")
    ap.add_argument("--max-samples", type=int, help="Limit dataset size (for testing)")
    args = ap.parse_args()

    # Decide dataset size
    if args.fast and not args.max_samples:
        args.max_samples = 100_000
        print("⚡ Fast mode: using 100,000 samples")

    df = load_dataset(args.data, max_samples=args.max_samples)
    X, y = df[SELECTED_FEATURES], df[TARGET].astype(int)

    # Handle imbalance
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    class_weight = {int(c): float(w) for c, w in zip(classes, weights)}

    pipe = build_pipeline()

    best_params = None
    if args.tuned:
        print("🔍 Running hyperparameter tuning...")
        pipe, best_params = tune_model(pipe, X, y, n_iter=10)

    # Final split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    # Train final model
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)

    print("\n📊 Classification Report:\n", classification_report(y_test, y_pred, digits=4))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    # Save model
    joblib.dump(pipe, args.model_out)

    # Save schema + params
    schema = {
        "selected_features": SELECTED_FEATURES,
        "categorical": CATEGORICAL,
        "numeric": NUMERIC,
        "class_weight": class_weight,
        "best_params": best_params
    }
    with open(args.schema_out, "w") as f:
        json.dump(schema, f, indent=2)

    print(f"💾 Saved model -> {args.model_out}")
    print(f"💾 Saved schema -> {args.schema_out}")


if __name__ == "__main__":
    main()
