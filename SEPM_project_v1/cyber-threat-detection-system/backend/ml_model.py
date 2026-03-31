"""Load trained model, predict, and explain with SHAP."""
import os
from typing import Optional

import joblib
import numpy as np

from feature_extraction import extract_from_log, row_to_feature_array, FEATURE_NAMES_ORDER

_bundle = None


def _root_dir():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_bundle():
    global _bundle
    if _bundle is not None:
        return _bundle
    path = os.path.join(_root_dir(), "model", "trained_model.pkl")
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"Model not found at {path}. Run: python backend/train_model.py"
        )
    _bundle = joblib.load(path)
    return _bundle


def predict_from_log(log_row):
    bundle = load_bundle()
    model = bundle["model"]
    proto_le = bundle["proto_le"]
    classes = bundle["classes"]

    feats = extract_from_log(log_row)
    X = row_to_feature_array(feats, proto_le)
    proba = model.predict_proba(X)[0]
    idx = int(np.argmax(proba))
    label = classes[idx]
    confidence = float(proba[idx])
    return {
        "label": label,
        "confidence": confidence,
        "probabilities": {classes[i]: float(proba[i]) for i in range(len(classes))},
        "features": feats,
    }


def explain_prediction(log_row, top_k=5):
    """SHAP TreeExplainer feature importance for this instance."""
    try:
        import shap
    except ImportError:
        return {
            "method": "fallback",
            "top_features": _fallback_explain(log_row),
        }

    bundle = load_bundle()
    model = bundle["model"]
    proto_le = bundle["proto_le"]
    feats = extract_from_log(log_row)
    X = row_to_feature_array(feats, proto_le)

    explainer = shap.TreeExplainer(model)
    sv = explainer.shap_values(X)
    pred = int(model.predict(X)[0])
    names = bundle.get("feature_names", FEATURE_NAMES_ORDER)
    n_feat = len(names)

    if isinstance(sv, list):
        raw = np.asarray(sv[pred], dtype=np.float64)
    else:
        raw = np.asarray(sv, dtype=np.float64)
    if raw.ndim >= 2:
        vals = np.ravel(raw[0])[:n_feat]
    else:
        vals = np.ravel(raw)[:n_feat]

    pairs = sorted(
        list(zip(names, vals)),
        key=lambda x: abs(float(x[1])),
        reverse=True,
    )[:top_k]
    return {
        "method": "SHAP",
        "top_features": [
            {"feature": n, "impact": round(float(v), 6)} for n, v in pairs
        ],
    }


def _fallback_explain(log_row):
    bundle = load_bundle()
    model = bundle["model"]
    names = bundle.get("feature_names", FEATURE_NAMES_ORDER)
    imps = getattr(model, "feature_importances_", None)
    if imps is None:
        return []
    pairs = sorted(zip(names, imps), key=lambda x: x[1], reverse=True)[:5]
    return [{"feature": n, "impact": round(float(v), 6)} for n, v in pairs]


_PRETTY_FEATURE = {
    "packet_count": "Packet count",
    "connection_duration": "Connection duration",
    "src_bytes": "Source bytes",
    "dst_bytes": "Destination bytes",
    "flow_rate": "Flow rate",
    "proto_encoded": "Protocol (encoded)",
}


def build_explanation_reason(
    explanation: Optional[dict],
    predicted_label: str,
    confidence: Optional[float] = None,
) -> dict:
    """Structured reason for UI: verdict, intro, ordered factors, method."""
    expl = explanation or {}
    method = (expl.get("method") or "").strip() or "contributions"
    feats = expl.get("top_features") or []
    conf_pct = round(float(confidence) * 100, 2) if confidence is not None else None
    conf_str = f"{conf_pct:.1f}%" if conf_pct is not None else "n/a"

    if method.upper() == "SHAP":
        basis = "SHAP values (how much each feature pushed this prediction)"
    elif method == "fallback":
        basis = "global feature importance (fallback — train SHAP for instance-level detail)"
    else:
        basis = f"{method} feature attributions"

    factors = []
    for i, f in enumerate(feats[:5], start=1):
        key = f.get("feature", "")
        name = _PRETTY_FEATURE.get(key, str(key).replace("_", " "))
        imp = float(f.get("impact", 0.0))
        if imp > 0:
            role = "Increases support for the predicted class vs. alternatives."
        elif imp < 0:
            role = "Decreases support for the predicted class relative to other labels."
        else:
            role = "Neutral influence on this split."
        factors.append(
            {
                "rank": i,
                "feature": key,
                "name": name,
                "impact": round(imp, 6),
                "role": role,
            }
        )

    if factors:
        intro = (
            f'Verdict: "{predicted_label}" with {conf_str} confidence. '
            f"Ranked below: strongest influences ({basis})."
        )
    else:
        intro = (
            f'Verdict: "{predicted_label}" ({conf_str} confidence). '
            "No per-feature attributions were returned for this row."
        )

    return {
        "verdict": predicted_label,
        "confidence_percent": conf_pct,
        "intro": intro,
        "factors": factors,
        "method": method,
        "has_factors": len(factors) > 0,
        "basis_label": basis,
    }


def format_reason_multiline(reason: Optional[dict]) -> str:
    """Plain multi-line text (logs, copy-paste, visual simulator)."""
    if not reason:
        return "No explanation available."
    lines = [reason.get("intro", ""), ""]
    if not reason.get("has_factors"):
        return lines[0].strip()
    lines.append("Ranked factors:")
    for fac in reason["factors"]:
        lines.append(
            f"  {fac['rank']}. {fac['name']}: impact {fac['impact']:+.4f} — {fac['role']}"
        )
    lines.append("")
    lines.append(f"Method: {reason.get('method', '')}")
    return "\n".join(lines)


def narrate_explanation(
    explanation: Optional[dict],
    predicted_label: str,
    confidence: Optional[float] = None,
) -> str:
    """Plain-text reason; prefer returning explanation_reason JSON to the client."""
    return format_reason_multiline(
        build_explanation_reason(explanation, predicted_label, confidence)
    )


def risk_from_confidence(confidence, predicted_label):
    if predicted_label == "Normal":
        return "Low"
    if confidence >= 0.85:
        return "Critical"
    if confidence >= 0.65:
        return "High"
    if confidence >= 0.45:
        return "Medium"
    return "Low"
