"""
Cyber Threat Detection System — Flask API and static frontend.
"""
import os
import sys

from flask import Flask, jsonify, redirect, request, send_from_directory, session

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth import (
    admin_create_user,
    delete_user,
    list_users_public,
    register_user,
    set_user_role,
    verify_user,
)
from simulation import (
    append_alert,
    append_log,
    read_alerts,
    read_logs,
    synthetic_flow_row,
)
from feature_extraction import extract_from_log
import ml_model

FRONTEND = os.path.join(ROOT, "frontend")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-cyber-threat-secret-change-me")
app.config["SESSION_COOKIE_HTTPONLY"] = True


def require_login():
    return session.get("user") is None


def admin_guard():
    """Return a Flask (response, status) tuple if the caller is not admin."""
    if require_login():
        return jsonify({"error": "Unauthorized"}), 401
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden", "message": "Administrator access required."}), 403
    return None


@app.route("/")
def index():
    return send_from_directory(FRONTEND, "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(FRONTEND, "login.html")


@app.route("/register")
def register_page():
    return send_from_directory(FRONTEND, "register.html")


@app.route("/dashboard")
def dashboard_page():
    return send_from_directory(FRONTEND, "dashboard.html")


@app.route("/simulator")
def simulator_page():
    return send_from_directory(FRONTEND, "simulator.html")


@app.route("/admin")
def admin_page():
    return send_from_directory(FRONTEND, "admin.html")


@app.route("/<path:filename>")
def static_files(filename):
    if filename.startswith("api/"):
        return jsonify({"error": "Not found"}), 404
    path = os.path.join(FRONTEND, filename)
    if os.path.isfile(path):
        return send_from_directory(FRONTEND, filename)
    return redirect("/")


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(force=True, silent=True) or {}
    ok, msg = register_user(
        ROOT,
        data.get("username"),
        data.get("password"),
        data.get("role", "user"),
    )
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    user = verify_user(ROOT, data.get("username"), data.get("password"))
    if not user:
        return jsonify({"ok": False, "message": "Invalid credentials."}), 401
    session["user"] = user["username"]
    session["role"] = user["role"]
    return jsonify({"ok": True, "user": user})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/session")
def api_session():
    if require_login():
        return jsonify({"authenticated": False}), 200
    return jsonify(
        {
            "authenticated": True,
            "username": session["user"],
            "role": session.get("role", "user"),
        }
    )


def _process_flow(ml_row, log_for_csv):
    """Run ML + optional alert."""
    try:
        pred = ml_model.predict_from_log(ml_row)
        expl = ml_model.explain_prediction(ml_row)
    except FileNotFoundError as e:
        return {
            "prediction": None,
            "explanation": None,
            "explanation_reason": None,
            "explanation_narrative": "",
            "error": str(e),
            "alert_created": False,
        }
    label = pred["label"]
    conf = pred["confidence"]
    risk = ml_model.risk_from_confidence(conf, label)
    top = expl.get("top_features") or []
    summary = "; ".join(
        f"{t['feature']} ({t['impact']:+.4f})" for t in top[:3]
    )

    alert_created = False
    if label != "Normal":
        append_alert(
            ROOT,
            {
                "timestamp": log_for_csv["time"],
                "attack_type": label,
                "source_ip": log_for_csv["src_ip"],
                "destination_ip": log_for_csv["dst_ip"],
                "risk_level": risk,
                "confidence": f"{conf:.4f}",
                "explanation_summary": summary[:500],
            },
        )
        alert_created = True

    reason = ml_model.build_explanation_reason(expl, label, conf)
    narrative = ml_model.format_reason_multiline(reason)
    return {
        "prediction": pred,
        "explanation": expl,
        "explanation_reason": reason,
        "explanation_narrative": narrative,
        "risk_level": risk,
        "alert_created": alert_created,
        "error": None,
    }


@app.route("/api/quick-simulation", methods=["POST"])
def api_quick_sim():
    if require_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    rnd = bool(data.get("random") or data.get("randomize"))
    row = synthetic_flow_row(
        data.get("source_device", "Laptop"),
        data.get("destination_device", "Server"),
        data.get("protocol", "TCP"),
        data.get("attack_type", "Normal"),
        int(data.get("num_packets") or 100),
        randomize=rnd,
    )
    append_log(ROOT, row)
    pkt_ml = row.get("_ml_packets", row["packets"])
    proto_ml = row.get("_ml_protocol", row["protocol"])
    ml_keys = {
        "protocol": proto_ml,
        "packets": pkt_ml,
        "connection_duration": row["connection_duration"],
        "src_bytes": row["src_bytes"],
        "dst_bytes": row["dst_bytes"],
        "flow_rate": row["flow_rate"],
    }
    result = _process_flow(ml_keys, row)
    log_out = {k: v for k, v in row.items() if not str(k).startswith("_")}
    out = {
        "log": log_out,
        "detection_packet_count": int(pkt_ml),
        "detection_protocol": str(proto_ml),
        "randomized": rnd,
        **result,
    }
    return jsonify(out)


@app.route("/api/visual-simulation", methods=["POST"])
def api_visual_sim():
    if require_login():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    flows = data.get("flows") or []
    global_rnd = bool(data.get("random") or data.get("randomize"))
    results = []
    for flow in flows:
        rnd = global_rnd or bool(flow.get("random") or flow.get("randomize"))
        row = synthetic_flow_row(
            flow.get("source_device", "Laptop"),
            flow.get("destination_device", "Server"),
            flow.get("protocol", "TCP"),
            flow.get("attack_type", "Normal"),
            int(flow.get("num_packets") or 100),
            src_ip=flow.get("src_ip"),
            dst_ip=flow.get("dst_ip"),
            randomize=rnd,
        )
        append_log(ROOT, row)
        pkt_ml = row.get("_ml_packets", row["packets"])
        proto_ml = row.get("_ml_protocol", row["protocol"])
        ml_keys = {
            "protocol": proto_ml,
            "packets": pkt_ml,
            "connection_duration": row["connection_duration"],
            "src_bytes": row["src_bytes"],
            "dst_bytes": row["dst_bytes"],
            "flow_rate": row["flow_rate"],
        }
        res = _process_flow(ml_keys, row)
        log_out = {k: v for k, v in row.items() if not str(k).startswith("_")}
        results.append(
            {
                "log": log_out,
                "detection_packet_count": int(pkt_ml),
                "detection_protocol": str(proto_ml),
                "randomized": rnd,
                **res,
            }
        )
    return jsonify({"results": results, "count": len(results)})


@app.route("/api/logs")
def api_logs():
    if require_login():
        return jsonify({"error": "Unauthorized"}), 401
    limit = int(request.args.get("limit", 300))
    return jsonify({"logs": read_logs(ROOT, limit=limit)})


@app.route("/api/alerts")
def api_alerts():
    if require_login():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"alerts": read_alerts(ROOT)})


@app.route("/api/predict-last", methods=["POST"])
def api_predict_last():
    if require_login():
        return jsonify({"error": "Unauthorized"}), 401
    logs = read_logs(ROOT, limit=1)
    if not logs:
        return jsonify({"error": "No logs"}), 400
    last = logs[-1]
    feats = extract_from_log(
        {
            "protocol": last.get("protocol"),
            "packets": last.get("packets"),
        }
    )
    dur = float(last.get("connection_duration") or 0.001)
    if dur <= 0:
        dur = 0.001
    pk = int(last.get("packets") or 0)
    synthetic = {
        **feats,
        "connection_duration": dur,
        "src_bytes": pk * 400,
        "dst_bytes": pk * 300,
        "flow_rate": pk / dur,
    }
    pred = ml_model.predict_from_log(synthetic)
    expl = ml_model.explain_prediction(synthetic)
    reason = ml_model.build_explanation_reason(
        expl, pred["label"], pred.get("confidence")
    )
    return jsonify(
        {
            "prediction": pred,
            "explanation": expl,
            "explanation_reason": reason,
            "explanation_narrative": ml_model.format_reason_multiline(reason),
        }
    )


@app.route("/api/chart-stats")
def api_chart_stats():
    if require_login():
        return jsonify({"error": "Unauthorized"}), 401
    logs = read_logs(ROOT, limit=2000)
    alerts = read_alerts(ROOT, limit=500)

    from collections import defaultdict

    attacks_over_time = defaultdict(int)
    for a in alerts:
        ts = (a.get("timestamp") or "")[:16]
        if ts:
            attacks_over_time[ts] += 1

    attack_dist = defaultdict(int)
    for a in alerts:
        attack_dist[a.get("attack_type", "Unknown")] += 1

    vol_by_hour = defaultdict(int)
    for row in logs:
        t = row.get("time", "")
        if len(t) >= 13:
            key = t[:13]
            try:
                vol_by_hour[key] += int(row.get("packets") or 0)
            except ValueError:
                vol_by_hour[key] += 0

    return jsonify(
        {
            "attacks_over_time": dict(sorted(attacks_over_time.items())),
            "attack_distribution": dict(attack_dist),
            "traffic_volume": dict(sorted(vol_by_hour.items())),
        }
    )


@app.route("/api/admin/users", methods=["GET"])
def api_admin_list_users():
    err = admin_guard()
    if err is not None:
        return err
    return jsonify({"users": list_users_public(ROOT)})


@app.route("/api/admin/users", methods=["POST"])
def api_admin_create_user():
    err = admin_guard()
    if err is not None:
        return err
    data = request.get_json(force=True, silent=True) or {}
    ok, msg = admin_create_user(
        ROOT,
        data.get("username"),
        data.get("password"),
        data.get("role", "user"),
    )
    return jsonify({"ok": ok, "message": msg, "users": list_users_public(ROOT)}), (
        200 if ok else 400
    )


@app.route("/api/admin/users/<username>", methods=["PATCH"])
def api_admin_update_user(username):
    err = admin_guard()
    if err is not None:
        return err
    data = request.get_json(force=True, silent=True) or {}
    if "role" in data:
        ok, msg = set_user_role(ROOT, username, data.get("role"))
        return jsonify(
            {"ok": ok, "message": msg, "users": list_users_public(ROOT)}
        ), (200 if ok else 400)
    return jsonify({"ok": False, "message": "No valid fields."}), 400


@app.route("/api/admin/users/<username>", methods=["DELETE"])
def api_admin_delete_user(username):
    err = admin_guard()
    if err is not None:
        return err
    ok, msg = delete_user(ROOT, username, session.get("user"))
    return jsonify({"ok": ok, "message": msg, "users": list_users_public(ROOT)}), (
        200 if ok else 400
    )


@app.route("/api/admin/database/logs", methods=["GET"])
def api_admin_database_logs():
    err = admin_guard()
    if err is not None:
        return err
    limit = min(int(request.args.get("limit", 500)), 5000)
    return jsonify({"logs": read_logs(ROOT, limit=limit)})


@app.route("/api/admin/database/alerts", methods=["GET"])
def api_admin_database_alerts():
    err = admin_guard()
    if err is not None:
        return err
    limit = min(int(request.args.get("limit", 500)), 5000)
    return jsonify({"alerts": read_alerts(ROOT, limit=limit)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
