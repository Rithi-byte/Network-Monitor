"""Map raw log rows to ML feature vectors aligned with UNSW-NB15 training."""


def protocol_key(proto):
    if proto is None:
        return "tcp"
    p = str(proto).strip().lower()
    if p in ("tcp", "udp", "icmp"):
        return p
    return p.split(".")[0][:10] if p else "tcp"


def extract_from_log(log_row):
    """
    log_row: dict with keys protocol, packets, and optional
    duration, src_bytes, dst_bytes, flow_rate (or derived).
    """
    packets = int(log_row.get("packets") or log_row.get("packet_count") or 0)
    dur = float(log_row.get("connection_duration") or log_row.get("dur") or 0.001)
    if dur <= 0:
        dur = 0.001
    sbytes = float(log_row.get("src_bytes") or log_row.get("sbytes") or 0)
    dbytes = float(log_row.get("dst_bytes") or log_row.get("dbytes") or 0)
    flow_rate = log_row.get("flow_rate")
    if flow_rate is None and dur > 0:
        flow_rate = packets / dur
    else:
        flow_rate = float(flow_rate or 0.0)

    return {
        "packet_count": float(packets),
        "connection_duration": dur,
        "protocol": protocol_key(log_row.get("protocol")),
        "src_bytes": sbytes,
        "dst_bytes": dbytes,
        "flow_rate": flow_rate,
    }


def row_to_feature_array(feature_dict, proto_le):
    """Single-row numpy-ready list in training column order."""
    import numpy as np

    proto = feature_dict["protocol"]
    try:
        pi = int(proto_le.transform([proto])[0])
    except ValueError:
        pi = int(proto_le.transform(["tcp"])[0])

    return np.array(
        [
            [
                feature_dict["packet_count"],
                feature_dict["connection_duration"],
                feature_dict["src_bytes"],
                feature_dict["dst_bytes"],
                feature_dict["flow_rate"],
                pi,
            ]
        ],
        dtype=np.float64,
    )


FEATURE_NAMES_ORDER = [
    "packet_count",
    "connection_duration",
    "src_bytes",
    "dst_bytes",
    "flow_rate",
    "proto_encoded",
]
