# LOGIN BASTION — Authentication Brute-Force Detector

A defensive Linux/OpenSSH log analyzer that identifies repeated failed authentication attempts by source IP and highlights sources that exceed a configurable threshold.

## Features
- Parses common OpenSSH `Failed password` log records.
- Groups failures by validated IPv4/IPv6 source address.
- Reports attempt counts and observed usernames.
- Supports allowlisting trusted source IPs and configurable alert thresholds.
- Produces a JSON report for analyst review; it never blocks IP addresses or changes firewall rules.

## Requirements
- Python 3.10 or later
- Python standard library only

## Run
```bash
python main.py sample.log --threshold 5
```

Read from standard input:
```bash
cat /var/log/auth.log | python main.py - --threshold 5
```

Use an allowlist file (one IP address per line):
```bash
python main.py /var/log/auth.log --threshold 5 --allowlist trusted-ips.txt --output report.json
```

## Validate
```bash
python -m unittest discover -s tests -v
python main.py --help
```

## Safe use
Run only against logs from systems you own or are authorized to monitor. The included sample uses documentation-only IP addresses and synthetic events. A flagged IP is an investigation lead, not proof of malicious activity. Review context before taking action.

## Portfolio context
Built for Anike-Moses Melie Jesse's defensive cybersecurity and cloud-security portfolio, demonstrating Python log parsing, authentication-event analysis, IP validation, CLI design, testing, and incident triage.
