"""Heuristic detection rules for common network attacks."""
import math

def calculate_entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def is_external(ip):
    """Assume internal IP range is 10.0.x.x."""
    return not str(ip).startswith("10.0.")

def check_rules(row):
    """
    Check if the given flow log triggers any heuristic rules.
    Returns a list of detected threat descriptions.
    """
    detected = []
    
    # SYN Flood: SYN-ACK Ratio > 10
    syn = float(row.get("syn_count", 0) or 0)
    ack = float(row.get("ack_count", 0) or 0)
    if syn > 0:
        ratio = syn / max(1.0, ack)
        if ratio > 10:
            detected.append(f"SYN Flood (Ratio: {ratio:.1f})")

    # UDP Flood: Packet Rate > 1000
    proto = str(row.get("protocol", "")).upper()
    pkts = float(row.get("packets", 0) or 0)
    dur = float(row.get("connection_duration", 0.001) or 0.001)
    if proto == "UDP" and (pkts / max(0.001, dur)) > 1000:
        detected.append(f"UDP Flood (Rate: {pkts/max(0.001, dur):.1f} pkts/s)")

    # ICMP Flood: Packet Count > 100
    if proto == "ICMP" and pkts > 100:
        detected.append(f"ICMP Flood (Packets: {int(pkts)})")

    # Data Exfiltration: Outbound Bytes > 5MB + External
    sbytes = float(row.get("src_bytes", 0) or 0)
    dst_ip = row.get("dst_ip", "")
    if sbytes > 5 * 1024 * 1024 and is_external(dst_ip):
        detected.append(f"Data Exfiltration (Volume: {sbytes/(1024*1024):.1f} MB to {dst_ip})")

    # DNS Tunneling: Length > 50 OR Entropy > 4.5
    dns_query = row.get("dns_query", "")
    if dns_query:
        if len(dns_query) > 50:
            detected.append(f"DNS Tunneling (Domain Length: {len(dns_query)})")
        elif calculate_entropy(dns_query) > 4.5:
            detected.append(f"DNS Tunneling (Entropy: {calculate_entropy(dns_query):.2f})")

    return detected
