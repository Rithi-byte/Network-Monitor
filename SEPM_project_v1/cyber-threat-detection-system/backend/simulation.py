"""Synthetic network traffic generation for quick and visual simulations."""
import csv
import json
import math
import os
import random
from datetime import datetime

LOG_FIELDS = ["time", "src_ip", "dst_ip", "protocol", "packets", "attack_type"]

DEVICE_PREFIX = {"Laptop": "10.0.1.", "Router": "10.0.0.", "Server": "10.0.2."}

# UI / log scenario labels -> keys in flow_calibration.json (UNSW-mapped classes)
_SCENARIO_TO_CAL = {
    "Normal": "Normal",
    "DoS": "DoS",
    "Port Scan": "Port Scan",
    "Brute Force": "Brute Force",
}

_SCENARIO_LABELS = tuple(_SCENARIO_TO_CAL.keys())
_DEVICE_TYPES = ("Laptop", "Router", "Server")

_CALIBRATION_CACHE = None
_EXEMPLARS_CACHE = None


def _project_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_flow_calibration():
    """Load per-class stats written by train_model.py; None if missing."""
    global _CALIBRATION_CACHE
    if _CALIBRATION_CACHE is not None:
        return _CALIBRATION_CACHE
    path = os.path.join(_project_root(), "model", "flow_calibration.json")
    if not os.path.isfile(path):
        _CALIBRATION_CACHE = {}
        return _CALIBRATION_CACHE
    with open(path, encoding="utf-8") as f:
        _CALIBRATION_CACHE = json.load(f)
    return _CALIBRATION_CACHE


def reset_flow_calibration_cache():
    global _CALIBRATION_CACHE, _EXEMPLARS_CACHE
    _CALIBRATION_CACHE = None
    _EXEMPLARS_CACHE = None


def load_class_exemplars():
    global _EXEMPLARS_CACHE
    if _EXEMPLARS_CACHE is not None:
        return _EXEMPLARS_CACHE
    path = os.path.join(_project_root(), "model", "class_exemplars.json")
    if not os.path.isfile(path):
        _EXEMPLARS_CACHE = {}
        return _EXEMPLARS_CACHE
    with open(path, encoding="utf-8") as f:
        _EXEMPLARS_CACHE = json.load(f)
    return _EXEMPLARS_CACHE


def _features_from_exemplar(ex):
    """
    Use a real UNSW row (tiny jitter). Scaling broke RF boundaries; this matches
    what the model was trained on.
    """
    j = random.uniform(0.997, 1.003)
    dur = max(float(ex["dur"]) * j, 1e-12)
    src_b = int(max(0.0, float(ex["sbytes"]) * j))
    dst_b = int(max(0.0, float(ex["dbytes"]) * j))
    rate = max(float(ex["rate"]) * j, 1e-6)
    pkt_ml = int(max(1, round(float(ex["packet_count"]))))
    return dur, src_b, dst_b, rate, pkt_ml


def _log_uniform(a, b):
    a, b = max(a, 1e-30), max(b, a * 1.000001)
    return 10 ** random.uniform(math.log10(a), math.log10(b))


def _effective_ml_packets(user_packets, packet_median, cal_key):
    """
    UNSW flows often have far fewer packets than UI slider values; cap so the RF
    sees feature scales it was trained on, while CSV still stores the user's count.
    """
    n = max(1, int(user_packets))
    pm = max(float(packet_median), 1.0)
    if cal_key == "Normal":
        hi = max(320.0, min(25000.0, pm * 28.0))
    elif cal_key == "DoS":
        hi = max(20.0, min(600.0, pm * 80.0))
    elif cal_key == "Port Scan":
        hi = max(90.0, min(3500.0, pm * 40.0))
    elif cal_key == "Brute Force":
        hi = max(20.0, min(900.0, pm * 90.0))
    else:
        hi = max(120.0, min(4000.0, pm * 30.0))
    return int(max(1, min(n, hi)))


def _features_from_calibration(attack_type, num_packets, cal_all):
    """Sample duration, bytes, and rate consistent with UNSW class marginals."""
    key = _SCENARIO_TO_CAL.get((attack_type or "").strip(), "Normal")
    default = cal_all.get("Normal") or {}
    bucket = cal_all.get(key) or default
    if not bucket:
        return None
    pm = max(float(bucket.get("packet_median", 1.0)), 1.0)
    pkt_user = max(1, int(num_packets))
    pkt = _effective_ml_packets(pkt_user, pm, key)
    dur_lo = max(float(bucket.get("dur_q25", 1e-6)), 1e-12)
    dur_hi = max(float(bucket.get("dur_q75", dur_lo * 10)), dur_lo * 1.0001)
    dur = _log_uniform(dur_lo, dur_hi)
    load = (pkt / pm) ** 0.42
    dur = dur / max(min(load, 5.0), 0.2)
    dur = max(dur, 1e-12)

    r_lo = max(float(bucket.get("rate_q25", 1e-6)), 1e-12)
    r_hi = max(float(bucket.get("rate_q75", r_lo * 10)), r_lo * 1.0001)
    r_prior = _log_uniform(r_lo, r_hi)
    r_flow = pkt / dur
    rate = 0.52 * r_flow + 0.48 * r_prior * random.uniform(0.88, 1.12)

    spp = max(float(bucket.get("sbytes_per_packet", 64)), 1.0)
    dpp = max(float(bucket.get("dbytes_per_packet", 64)), 1.0)
    src_b = int(max(0.0, pkt * spp * random.uniform(0.78, 1.22)))
    dst_b = int(max(0.0, pkt * dpp * random.uniform(0.78, 1.22)))
    return dur, src_b, dst_b, rate, pkt


def _random_host(prefix):
    return prefix + str(random.randint(2, 250))


def _bytes_for_attack(attack, packets, base_packet_size=512):
    if attack == "Normal":
        mul = random.uniform(0.8, 1.2)
    elif attack == "DoS":
        mul = random.uniform(3.0, 8.0)
    elif attack == "Port Scan":
        mul = random.uniform(0.1, 0.4)
    elif attack == "Brute Force":
        mul = random.uniform(1.5, 3.0)
    else:
        mul = random.uniform(1.0, 2.0)
    total = int(packets * base_packet_size * mul)
    split = random.uniform(0.3, 0.7)
    src_b = int(total * split)
    dst_b = total - src_b
    return src_b, dst_b


def _duration(attack, packets):
    if attack == "DoS":
        return max(0.00001, packets / random.uniform(500000, 2_000_000))
    if attack == "Port Scan":
        return max(0.001, packets / random.uniform(5000, 50000))
    if attack == "Brute Force":
        return max(0.01, packets / random.uniform(100, 5000))
    return max(0.0001, packets / random.uniform(10000, 200000))


def synthetic_flow_row(
    src_device,
    dst_device,
    protocol,
    attack_type,
    num_packets,
    src_ip=None,
    dst_ip=None,
    randomize=False,
):
    if randomize:
        attack_type = random.choice(_SCENARIO_LABELS)
        protocol = random.choice(("TCP", "UDP", "ICMP"))
        num_packets = random.randint(80, 9500)
        src_device = random.choice(_DEVICE_TYPES)
        rest = [d for d in _DEVICE_TYPES if d != src_device]
        dst_device = random.choice(rest)
        src_ip = None
        dst_ip = None

    proto = (protocol or "TCP").upper()
    if proto not in ("TCP", "UDP", "ICMP"):
        proto = "TCP"
    attack = attack_type or "Normal"
    n = max(1, int(num_packets))

    if src_ip is None:
        src_ip = _random_host(DEVICE_PREFIX.get(src_device, "10.0.1."))
    if dst_ip is None:
        dst_ip = _random_host(DEVICE_PREFIX.get(dst_device, "10.0.2."))

    cal = load_flow_calibration()
    exemplars = load_class_exemplars()
    key = _SCENARIO_TO_CAL.get((attack or "").strip(), "Normal")
    bucket = (cal or {}).get(key) or (cal or {}).get("Normal") or {}
    pm = max(float(bucket.get("packet_median", 1.0)), 1.0) if bucket else 1.0

    ex_list = exemplars.get(key) if exemplars else None
    ml_proto = proto.lower()
    if ex_list:
        ex = random.choice(ex_list)
        dur, src_b, dst_b, flow_rate, pkt_ml = _features_from_exemplar(ex)
        ml_proto = (ex.get("proto") or ml_proto).lower()
    else:
        pkt_ml = _effective_ml_packets(n, pm, key)
        sampled = _features_from_calibration(attack, n, cal) if cal else None
        if sampled:
            dur, src_b, dst_b, flow_rate, pkt_ml = sampled
        else:
            dur = _duration(attack, n)
            src_b, dst_b = _bytes_for_attack(attack, n)
            flow_rate = n / dur if dur > 0 else float(n)
            pkt_ml = n

    row = {
        "time": datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "packets": n,
        "_ml_packets": pkt_ml,
        "_ml_protocol": ml_proto,
        "attack_type": attack,
        "connection_duration": dur,
        "src_bytes": src_b,
        "dst_bytes": dst_b,
        "flow_rate": flow_rate,
    }
    return row


def append_log(root_dir, row):
    path = os.path.join(root_dir, "database", "logs.csv")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    write_header = not os.path.isfile(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        if write_header:
            w.writeheader()
        w.writerow(
            {
                "time": row["time"],
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "protocol": row["protocol"],
                "packets": row["packets"],
                "attack_type": row["attack_type"],
            }
        )
    return row


def append_alert(root_dir, alert):
    path = os.path.join(root_dir, "database", "alerts.csv")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fields = [
        "timestamp",
        "attack_type",
        "source_ip",
        "destination_ip",
        "risk_level",
        "confidence",
        "explanation_summary",
    ]
    write_header = not os.path.isfile(path) or os.path.getsize(path) == 0
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if write_header:
            w.writeheader()
        w.writerow(alert)


def read_logs(root_dir, limit=500):
    path = os.path.join(root_dir, "database", "logs.csv")
    if not os.path.isfile(path):
        return []
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows[-limit:]


def read_alerts(root_dir, limit=200):
    path = os.path.join(root_dir, "database", "alerts.csv")
    if not os.path.isfile(path):
        return []
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return list(reversed(rows[-limit:]))
