"""Replay exported logs through every rule.

Usage:
  python -m detectionlab.scan events.jsonl            # one JSON event per line
  python -m detectionlab.scan events.json --rules rules/aws

Export Sysmon events from your SIEM (or CloudTrail records from S3) as JSON, then run this
to see which rules fire, without needing the SIEM's own query language.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from detectionlab.matcher import load_rules


def read_events(path: Path) -> list[dict]:
    text = path.read_text()
    stripped = text.lstrip()
    if stripped.startswith("["):
        return json.loads(stripped)
    if stripped.startswith("{") and '"Records"' in stripped[:200]:
        return json.loads(stripped)["Records"]  # raw CloudTrail file
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("events", type=Path)
    parser.add_argument("--rules", type=Path, default=Path("rules"))
    args = parser.parse_args(argv)

    rules = load_rules(args.rules)
    events = read_events(args.events)
    hits: Counter[str] = Counter()
    for i, event in enumerate(events, 1):
        for rule in rules:
            if rule.matches(event):
                hits[rule.title] += 1
                print(f"[{rule.level.upper():8}] event {i}: {rule.title}")

    print(f"\n{len(events)} events, {len(rules)} rules, {sum(hits.values())} alerts")
    for title, count in hits.most_common():
        print(f"  {count:5}  {title}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
