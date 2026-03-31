"""
Train RandomForest on UNSW-NB15 (local dataset) and save model/trained_model.pkl.
Maps dataset attack categories to: Normal, DoS, Port Scan, Brute Force, Other attacks.
Also writes flow_calibration.json for synthetic traffic aligned to each class.
"""
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

CLASSES = ["Normal", "DoS", "Port Scan", "Brute Force", "Other attacks"]


def map_attack_category(cat: str) -> str:
    c = (cat or "").strip()
    if c == "Normal":
        return "Normal"
    if c == "DoS":
        return "DoS"
    if c == "Reconnaissance":
        return "Port Scan"
    if c == "Generic":
        return "Brute Force"
    return "Other attacks"


def build_flow_calibration(df: pd.DataFrame) -> dict:
    """Per-class flow stats so simulations match UNSW feature distributions."""
    cal = {}
    global_sub = df
    for cls in CLASSES:
        sub = df[df["y_label"] == cls]
        if len(sub) < 80:
            sub = df[df["y_label"] == "Other attacks"]
        if len(sub) < 80:
            sub = global_sub

        pc_med = float(np.nanmedian(sub["packet_count"]) or 1.0)
        pc_med = max(pc_med, 1.0)
        pkt_safe = sub["packet_count"].clip(lower=1)
        spp = float(np.nanmedian((sub["sbytes"] / pkt_safe).replace([np.inf, -np.inf], np.nan)) or 64.0)
        dpp = float(np.nanmedian((sub["dbytes"] / pkt_safe).replace([np.inf, -np.inf], np.nan)) or 64.0)

        cal[cls] = {
            "packet_median": pc_med,
            "dur_q25": float(max(sub["dur"].quantile(0.25), 1e-10)),
            "dur_q75": float(max(sub["dur"].quantile(0.75), 1e-9)),
            "rate_q25": float(max(sub["rate"].quantile(0.25), 1e-6)),
            "rate_q75": float(max(sub["rate"].quantile(0.75), 1e-6)),
            "sbytes_per_packet": max(spp, 1.0),
            "dbytes_per_packet": max(dpp, 1.0),
        }
    return cal


def build_class_exemplars(
    df: pd.DataFrame,
    clf: RandomForestClassifier,
    proto_le: LabelEncoder,
    per_class: int = 80,
    seed: int = 42,
) -> dict:
    """
    Real UNSW rows that the trained model already classifies correctly, so
    simulated flows reproduce decision boundaries.
    """
    rng = np.random.default_rng(seed)
    name_to_id = {n: i for i, n in enumerate(CLASSES)}
    out = {}
    proto_enc_all = proto_le.transform(df["proto"].astype(str).str.lower())
    for cls in CLASSES:
        sub = df[df["y_label"] == cls]
        if len(sub) == 0:
            continue
        want = name_to_id[cls]
        pos = sub.index
        X = np.column_stack(
            [
                sub["packet_count"].values,
                sub["dur"].values,
                sub["sbytes"].values,
                sub["dbytes"].values,
                sub["rate"].values,
                proto_enc_all[df.index.get_indexer(pos)],
            ]
        ).astype(np.float64)
        pred = clf.predict(X)
        proba = clf.predict_proba(X)
        conf_ok = proba[:, want] >= 0.5
        pool = sub[(pred == want) & conf_ok]
        if len(pool) < 15:
            pool = sub[pred == want]
        if len(pool) < 15:
            pool = sub
        n_take = min(per_class, len(pool))
        if n_take == 0:
            continue
        pick = rng.choice(len(pool), size=n_take, replace=False)
        rows = pool.iloc[pick]
        out[cls] = [
            {
                "packet_count": float(r["packet_count"]),
                "dur": float(max(r["dur"], 1e-12)),
                "sbytes": float(max(r["sbytes"], 0)),
                "dbytes": float(max(r["dbytes"], 0)),
                "rate": float(max(r["rate"], 0)),
                "proto": str(r["proto"]).lower(),
            }
            for _, r in rows.iterrows()
        ]
    return out


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dataset_path = os.path.join(
        os.path.dirname(root), "dataset", "UNSW_NB15_training-set.csv"
    )
    if not os.path.isfile(dataset_path):
        # workspace layout: SEPM_project/cyber-threat-detection-system and SEPM_project/dataset
        alt = os.path.join(root, "..", "dataset", "UNSW_NB15_training-set.csv")
        dataset_path = os.path.normpath(alt)
    if not os.path.isfile(dataset_path):
        print("Training CSV not found:", dataset_path, file=sys.stderr)
        sys.exit(1)

    print("Loading", dataset_path)
    df = pd.read_csv(dataset_path, low_memory=False)
    df["attack_cat"] = df["attack_cat"].astype(str).str.strip()
    df["y_label"] = df["attack_cat"].map(map_attack_category)

    df["packet_count"] = df["spkts"].fillna(0).astype(float) + df["dpkts"].fillna(
        0
    ).astype(float)
    df["dur"] = pd.to_numeric(df["dur"], errors="coerce").fillna(0.001)
    df.loc[df["dur"] <= 0, "dur"] = 0.001
    df["sbytes"] = pd.to_numeric(df["sbytes"], errors="coerce").fillna(0)
    df["dbytes"] = pd.to_numeric(df["dbytes"], errors="coerce").fillna(0)
    df["rate"] = pd.to_numeric(df["rate"], errors="coerce").fillna(0)
    df["proto"] = df["proto"].astype(str).str.lower()

    proto_le = LabelEncoder()
    df["proto_enc"] = proto_le.fit_transform(df["proto"])

    X = df[
        ["packet_count", "dur", "sbytes", "dbytes", "rate", "proto_enc"]
    ].values.astype(np.float64)
    name_to_id = {n: i for i, n in enumerate(CLASSES)}
    y_multiclass = df["y_label"].map(
        lambda n: name_to_id.get(n, CLASSES.index("Other attacks"))
    )
    y_multiclass = y_multiclass.astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_multiclass, test_size=0.2, random_state=42, stratify=y_multiclass
    )

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=24,
        min_samples_leaf=2,
        random_state=42,
        class_weight="balanced_subsample",
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    acc = clf.score(X_test, y_test)
    print("Hold-out accuracy:", round(acc, 4))

    model_dir = os.path.join(root, "model")
    os.makedirs(model_dir, exist_ok=True)
    out_path = os.path.join(model_dir, "trained_model.pkl")
    bundle = {
        "model": clf,
        "proto_le": proto_le,
        "classes": CLASSES,
        "feature_names": [
            "packet_count",
            "connection_duration",
            "src_bytes",
            "dst_bytes",
            "flow_rate",
            "proto_encoded",
        ],
    }
    joblib.dump(bundle, out_path)
    print("Saved", out_path)

    cal_path = os.path.join(model_dir, "flow_calibration.json")
    cal = build_flow_calibration(df)
    with open(cal_path, "w", encoding="utf-8") as f:
        json.dump(cal, f, indent=2)
    print("Saved", cal_path)

    ex_path = os.path.join(model_dir, "class_exemplars.json")
    exemplars = build_class_exemplars(
        df, clf, proto_le, per_class=120, seed=42
    )
    with open(ex_path, "w", encoding="utf-8") as f:
        json.dump(exemplars, f, indent=2)
    print("Saved", ex_path)


if __name__ == "__main__":
    main()
