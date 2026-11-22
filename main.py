from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import re
import sys
from pathlib import Path

FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)


def load_allowlist(path: str | None) -> set[str]:
    if not path:
        return set()
    allowed: set[str] = set()
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        try:
            allowed.add(str(ipaddress.ip_address(value)))
        except ValueError:
            continue
    return allowed


def analyze(text: str, threshold: int = 5, allowlist: set[str] | None = None) -> dict:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    allowed = allowlist or set()
    by_ip: dict[str, collections.Counter] = {}
    total = 0
    malformed_ip_events = 0

    for line in text.splitlines():
        match = FAILED_PASSWORD.search(line)
        if not match:
            continue
        raw_ip = match.group("ip")
        try:
            source_ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            malformed_ip_events += 1
            continue
        if source_ip in allowed:
            continue
        username = match.group("username")
        bucket = by_ip.setdefault(source_ip, collections.Counter())
        bucket[username] += 1
        total += 1

    sources = []
    for source_ip, usernames in sorted(by_ip.items(), key=lambda item: (-sum(item[1].values()), item[0])):
        failures = sum(usernames.values())
        sources.append({
            "ip": source_ip,
            "failures": failures,
            "usernames": dict(usernames.most_common()),
            "threshold_exceeded": failures >= threshold,
        })

    return {
        "threshold": threshold,
        "total_failed_events": total,
        "unique_source_ips": len(by_ip),
        "suspicious_sources": [item for item in sources if item["threshold_exceeded"]],
        "all_sources": sources,
        "allowlisted_sources_excluded": len(allowed),
        "malformed_ip_events_ignored": malformed_ip_events,
        "note": "A threshold alert is a triage signal, not proof of malicious activity. No blocking action is performed.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect repeated failed OpenSSH/Linux authentication attempts by source IP."
    )
    parser.add_argument("target", nargs="?", default="-", help="Log file path; use - or omit to read stdin")
    parser.add_argument("--threshold", type=int, default=5, help="Minimum failures from one IP to flag (default: 5)")
    parser.add_argument("--allowlist", help="Optional file containing trusted IP addresses, one per line")
    parser.add_argument("--output", help="Optional path for a JSON report")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.target == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(args.target).read_text(encoding="utf-8", errors="replace")

    report = analyze(raw, threshold=args.threshold, allowlist=load_allowlist(args.allowlist))
    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
