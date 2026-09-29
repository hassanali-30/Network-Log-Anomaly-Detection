#!/usr/bin/env python3
"""Offline network-log anomaly detection with explainable findings.

The tool reads local CSV or JSON logs only. It never captures traffic, probes
hosts, contacts threat-intelligence services, or blocks network activity.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class NetworkEvent:
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int | None
    protocol: str
    bytes: int
    action: str
    dns_query: str | None = None


FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "@timestamp", "ts"),
    "src_ip": ("src_ip", "source_ip", "src", "source.address", "id.orig_h"),
    "dst_ip": ("dst_ip", "destination_ip", "dst", "destination.address", "id.resp_h"),
    "dst_port": ("dst_port", "destination_port", "dport", "id.resp_p"),
    "protocol": ("protocol", "proto", "network.transport"),
    "bytes": ("bytes", "byte_count", "network.bytes", "orig_bytes"),
    "action": ("action", "event_action", "verdict", "result"),
    "dns_query": ("dns_query", "query", "query_name", "dns.question.name"),
}


def first_value(row: dict[str, Any], aliases: tuple[str, ...], default: Any = "") -> Any:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for alias in aliases:
        if alias.lower() in lowered and lowered[alias.lower()] not in (None, ""):
            return lowered[alias.lower()]
    return default


def parse_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()


def normalize_row(row: dict[str, Any]) -> NetworkEvent:
    timestamp = parse_timestamp(first_value(row, FIELD_ALIASES["timestamp"]))
    src_ip = str(first_value(row, FIELD_ALIASES["src_ip"], "unknown-src"))
    dst_ip = str(first_value(row, FIELD_ALIASES["dst_ip"], "unknown-dst"))
    raw_port = first_value(row, FIELD_ALIASES["dst_port"], "")
    dst_port = int(float(raw_port)) if str(raw_port).strip() else None
    raw_bytes = first_value(row, FIELD_ALIASES["bytes"], 0)
    byte_count = max(0, int(float(raw_bytes or 0)))
    return NetworkEvent(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=str(first_value(row, FIELD_ALIASES["protocol"], "unknown")).lower(),
        bytes=byte_count,
        action=str(first_value(row, FIELD_ALIASES["action"], "unknown")).lower(),
        dns_query=str(first_value(row, FIELD_ALIASES["dns_query"], "")) or None,
    )


def load_events(path: str | Path) -> list[NetworkEvent]:
    file_path = Path(path)
    if file_path.suffix.lower() == ".json":
        data = json.loads(file_path.read_text(encoding="utf-8"))
        rows = data if isinstance(data, list) else data.get("events", [])
    else:
        with file_path.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
    if not isinstance(rows, list):
        raise ValueError("Input must be a list of events or a CSV table")
    return [normalize_row(row) for row in rows]


def z_score(value: float, values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    deviation = statistics.pstdev(values)
    return 0.0 if deviation == 0 else (value - statistics.mean(values)) / deviation


def finding(kind: str, severity: str, source: str, detail: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": kind,
        "severity": severity,
        "source": source,
        "detail": detail,
        "evidence": evidence,
    }


def detect_anomalies(events: Iterable[NetworkEvent], window_seconds: int = 300) -> dict[str, Any]:
    event_list = sorted(events, key=lambda item: item.timestamp)
    if window_seconds < 10:
        raise ValueError("window_seconds must be at least 10")
    by_source: dict[str, list[NetworkEvent]] = defaultdict(list)
    by_source_window: dict[tuple[str, int], list[NetworkEvent]] = defaultdict(list)
    destination_counts = Counter((event.src_ip, event.dst_ip) for event in event_list)
    for event in event_list:
        by_source[event.src_ip].append(event)
        window = int(event.timestamp // window_seconds)
        by_source_window[(event.src_ip, window)].append(event)

    findings: list[dict[str, Any]] = []
    for (source, destination), count in destination_counts.items():
        if count == 1:
            event = next(item for item in by_source[source] if item.dst_ip == destination)
            findings.append(finding(
                "rare-destination", "low", source,
                "Destination occurred once in the input window.",
                {"destination": destination, "timestamp": event.timestamp},
            ))

    for source, source_events in by_source.items():
        ports = {event.dst_port for event in source_events if event.dst_port is not None}
        destinations = {event.dst_ip for event in source_events}
        if len(ports) >= 10:
            findings.append(finding(
                "possible-port-scan", "medium", source,
                f"Source contacted {len(ports)} distinct destination ports.",
                {"distinct_ports": sorted(ports), "destinations": len(destinations)},
            ))

    window_bytes: dict[str, dict[int, int]] = defaultdict(dict)
    for (source, window), window_events in by_source_window.items():
        window_bytes[source][window] = sum(event.bytes for event in window_events)
    for source, values in window_bytes.items():
        baseline = list(values.values())
        for window, total in values.items():
            score = z_score(total, baseline)
            if score >= 3 and total > 0:
                findings.append(finding(
                    "traffic-spike", "high" if score >= 4 else "medium", source,
                    f"Window traffic is {score:.2f} standard deviations above its source baseline.",
                    {"window": window, "bytes": total, "z_score": round(score, 3)},
                ))

    for source, source_events in by_source.items():
        pair_windows: dict[tuple[str, str], set[int]] = defaultdict(set)
        for event in source_events:
            pair_windows[(event.src_ip, event.dst_ip)].add(int(event.timestamp // window_seconds))
        for (_, destination), windows in pair_windows.items():
            if len(windows) >= 4:
                findings.append(finding(
                    "repeated-beacon-candidate", "medium", source,
                    "Source-destination pair appeared in four or more time windows.",
                    {"destination": destination, "windows": sorted(windows)},
                ))

    ml_findings = optional_isolation_forest(by_source_window, window_seconds)
    findings.extend(ml_findings)
    severity_counts = Counter(item["severity"] for item in findings)
    return {
        "tool": "Network Log Anomaly Detection",
        "version": "1.0.0",
        "offline_only": True,
        "network_activity_performed": False,
        "event_count": len(event_list),
        "time_window_seconds": window_seconds,
        "time_range": {
            "start": event_list[0].timestamp if event_list else None,
            "end": event_list[-1].timestamp if event_list else None,
        },
        "baseline": {
            "sources": len(by_source),
            "source_windows": len(by_source_window),
            "bytes": sum(event.bytes for event in event_list),
        },
        "anomaly_count": len(findings),
        "severity_counts": dict(severity_counts),
        "findings": findings,
        "limitations": [
            "Anomaly means unusual for this input baseline, not malicious.",
            "Short or biased logs reduce baseline quality.",
            "Validate findings with asset context and approved telemetry.",
        ],
    }


def optional_isolation_forest(
    by_source_window: dict[tuple[str, int], list[NetworkEvent]],
    window_seconds: int,
) -> list[dict[str, Any]]:
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return []
    keys = list(by_source_window)
    if len(keys) < 8:
        return []
    features = []
    for source, window in keys:
        rows = by_source_window[(source, window)]
        features.append([
            len(rows),
            sum(item.bytes for item in rows),
            len({item.dst_ip for item in rows}),
            len({item.dst_port for item in rows if item.dst_port is not None}),
        ])
    model = IsolationForest(
        n_estimators=100, contamination="auto", random_state=42
    )
    labels = model.fit_predict(features)
    scores = model.decision_function(features)
    results = []
    for index, label in enumerate(labels):
        if label == -1:
            source, window = keys[index]
            results.append(finding(
                "ml-outlier-window", "medium", source,
                "Isolation Forest marked this source-time window as unusual.",
                {
                    "window": window,
                    "window_seconds": window_seconds,
                    "model_score": round(float(scores[index]), 5),
                    "features": {
                        "events": features[index][0],
                        "bytes": features[index][1],
                        "unique_destinations": features[index][2],
                        "unique_ports": features[index][3],
                    },
                },
            ))
    return results


def render_html(report: dict[str, Any]) -> str:
    rows = []
    for item in report["findings"]:
        rows.append(
            "<tr><td>{severity}</td><td>{kind}</td><td>{source}</td><td>{detail}</td><td>{evidence}</td></tr>".format(
                severity=html.escape(str(item["severity"])),
                kind=html.escape(str(item["type"])),
                source=html.escape(str(item["source"])),
                detail=html.escape(str(item["detail"])),
                evidence=html.escape(json.dumps(item["evidence"])),
            )
        )
    return f"""<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Network Anomaly Report</title>
<style>body{{font:16px system-ui;margin:2rem;color:#172033}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd;padding:.55rem;text-align:left;vertical-align:top}}th{{background:#eaf1fb}}.warning{{color:#9b2c2c}}</style>
<h1>Network Log Anomaly Report</h1>
<p><strong>Events:</strong> {report["event_count"]} &nbsp; <strong>Anomalies:</strong> {report["anomaly_count"]}</p>
<p class="warning">Offline, heuristic analysis. Anomalies require analyst validation.</p>
<table><tr><th>Severity</th><th>Type</th><th>Source</th><th>Detail</th><th>Evidence</th></tr>{''.join(rows)}</table>
</html>"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline network-log anomaly detector")
    parser.add_argument("input", help="CSV or JSON network log")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--format", choices={"json", "html", "text"}, default="text")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        report = detect_anomalies(load_events(args.input), args.window_seconds)
        if args.format == "json":
            output = json.dumps(report, indent=2)
        elif args.format == "html":
            output = render_html(report)
        else:
            print(f"Events:    {report['event_count']}")
            print(f"Anomalies: {report['anomaly_count']}")
            print(f"Severity:  {report['severity_counts']}")
            for item in report["findings"]:
                print(f"[{item['severity']}] {item['type']}: {item['detail']}")
            return 0
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output)
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
