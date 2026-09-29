# Security Policy

This project is offline defensive analytics.

## Safety boundaries

The analyzer:

- reads local CSV or JSON logs only
- never captures packets or contacts a network
- never scans, blocks, or changes network activity
- does not upload logs to external services
- may expose IP addresses, DNS names, and timestamps in reports

Use sanitized data in public issues and protect reports according to your organization's privacy policy.

## Reporting

Use a private security report when possible. Do not publish credentials, tokens, personal data, or raw sensitive logs.