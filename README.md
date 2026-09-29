# Network Log Anomaly Detection

[![CI](https://github.com/hassanali-30/Network-Log-Anomaly-Detection/actions/workflows/ci.yml/badge.svg)](https://github.com/hassanali-30/Network-Log-Anomaly-Detection/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

An offline, explainable analytics tool for detecting unusual behavior in CSV and JSON network logs. It builds source/time-window baselines and reports possible port scans, traffic spikes, repeated-beacon candidates, rare destinations, and optional Isolation Forest outliers.

> **Safety boundary:** The analyzer reads local logs only. It never captures packets, scans hosts, blocks traffic, uploads data, or contacts external services.

## Features

- CSV, JSON, and common Zeek-style field aliases
- Timestamp and byte-count normalization
- Configurable time-window baselines
- Possible port-scan detection
- Traffic-spike detection with z-scores
- Repeated source-destination window analysis
- Rare-destination signals
- Optional Isolation Forest outlier detection
- Explainable evidence for every finding
- JSON, HTML, and terminal reports
- Sample input, tests, CI, security policy, and license

## Installation

Requires Python 3.10 or newer.

```
git clone https://github.com/hassanali-30/Network-Log-Anomaly-Detection.git
cd Network-Log-Anomaly-Detection
python -m venv .venv
```

Activate the environment:

**Windows PowerShell**

```
.venv\\Scripts\\Activate.ps1
```

**macOS/Linux**

```
source .venv/bin/activate
```

Install the analyzer and optional ML dependency:

```
python -m pip install -r requirements.txt
```

## Run

Analyze the included sample:

```
python network_anomaly_detector.py sample_logs.csv
```

Create a JSON report:

```
python network_anomaly_detector.py sample_logs.csv --format json --output report.json
```

Create an HTML report:

```
python network_anomaly_detector.py sample_logs.csv --format html --output report.html
```

Use a different baseline window:

```
python network_anomaly_detector.py network_logs.csv --window-seconds 600 --format json
```

## Input format

CSV example:

```
timestamp,src_ip,dst_ip,dst_port,protocol,bytes,action,dns_query
2026-01-01T00:00:00Z,10.0.0.10,10.0.0.20,443,tcp,1200,allowed,
```

The normalizer also recognizes common aliases such as `@timestamp`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `orig_bytes`, and `proto`.

## Detection logic

- **Possible port scan:** a source contacts at least 10 distinct destination ports.
- **Traffic spike:** a source/time window is at least three standard deviations above its own observed byte baseline.
- **Repeated-beacon candidate:** a source-destination pair appears in at least four time windows.
- **Rare destination:** a destination appears once in the supplied input.
- **ML outlier:** optional Isolation Forest marks a source/time window as unusual using event count, bytes, unique destinations, and unique ports.

These are triage signals, not proof of compromise. Baseline quality depends on log duration, asset roles, traffic seasonality, and clean labeling.

## Project layout

```
network_anomaly_detector.py  # Analyzer and report generator
sample_logs.csv              # Safe synthetic example
tests/                       # Offline unit tests
SECURITY.md                  # Defensive-use policy
```

## Testing

```
python -m pytest -q
```

## Limitations

Anomaly detection is not a guaranteed accuracy score. Evaluate it against a labeled, representative, held-out dataset and report precision, recall, F1-score, false-positive rate, and detection delay before using it operationally.

## License

See [LICENSE](LICENSE).
