from network_anomaly_detector import (
    NetworkEvent,
    detect_anomalies,
    normalize_row,
)


def test_normalize_common_fields():
    event = normalize_row({
        "@timestamp": "2026-01-01T00:00:00Z",
        "id.orig_h": "10.0.0.1",
        "id.resp_h": "10.0.0.2",
        "id.resp_p": "443",
        "proto": "TCP",
        "orig_bytes": "1200",
        "action": "allowed",
    })
    assert event.src_ip == "10.0.0.1"
    assert event.dst_port == 443
    assert event.bytes == 1200


def test_port_scan_and_rare_destination():
    records = [
        NetworkEvent(float(i), "10.0.0.5", f"10.0.0.{i}", 1000 + i, "tcp", 50, "allowed")
        for i in range(1, 12)
    ]
    report = detect_anomalies(records, window_seconds=60)
    kinds = {item["type"] for item in report["findings"]}
    assert "possible-port-scan" in kinds
    assert "rare-destination" in kinds


def test_repeated_beacon_candidate():
    records = [
        NetworkEvent(float(i * 300), "10.0.0.5", "10.0.0.9", 443, "tcp", 100, "allowed")
        for i in range(4)
    ]
    report = detect_anomalies(records, window_seconds=300)
    assert any(item["type"] == "repeated-beacon-candidate" for item in report["findings"])


def test_offline_boundary():
    report = detect_anomalies([], window_seconds=300)
    assert report["offline_only"] is True
    assert report["network_activity_performed"] is False
