# Detection Lab

[![CI](https://github.com/SincerelyBrittany/my-first-detection-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/SincerelyBrittany/my-first-detection-lab/actions/workflows/ci.yml)

> Detection-as-code for a home SOC lab: Sigma rules for Windows (Sysmon) and AWS CloudTrail, each one tested in CI against attack and normal-activity events.

**Status:** Building. All rules pass their tests; live runs against the lab are in progress.  **Track:** Security

## The problem

Security teams don't just need alerts. They need alerts they can trust. A rule that fires on every Defender scan gets ignored, and a rule nobody tested quietly misses the real attack. This lab treats detections like code: each rule lives in version control, comes with evidence of what it should and shouldn't catch, and can't be merged if that evidence fails.

It's the follow-on to [PhishTriage](https://github.com/SincerelyBrittany/phishtriage): PhishTriage flags the phishing email, and the first rule here catches the attachment running if someone opens it anyway.

## What's in it

| Path | What it is |
| --- | --- |
| `rules/windows/` | Sigma rules for Sysmon process and memory-access events |
| `rules/aws/` | Sigma rules for AWS CloudTrail |
| `tests/fixtures/<rule>/malicious/` | Events the rule **must** fire on |
| `tests/fixtures/<rule>/benign/` | Normal activity the rule **must not** fire on |
| `detectionlab/matcher.py` | A small Sigma evaluator so rules can be tested without a SIEM |
| `detectionlab/scan.py` | Replays exported logs (JSON, JSONL or raw CloudTrail files) through every rule |
| `docs/coverage.md` | Generated ATT&CK coverage map, including what's **not** covered yet |
| `docs/setup.md` | How to build the lab: Windows VM, Sysmon, Splunk or Elastic, Atomic Red Team, AWS sandbox |

## Rules

| Rule | ATT&CK | Source | Why it matters |
| --- | --- | --- | --- |
| Office app spawns a shell | T1204.002, T1566.001 | Sysmon 1 | The usual next step after a malicious attachment is opened |
| PowerShell encoded command | T1059.001, T1027 | Sysmon 1 | Attackers base64-encode commands to hide them |
| Suspicious LSASS access | T1003.001 | Sysmon 10 | Credential dumping (Mimikatz-style) |
| Scheduled task from a risky path | T1053.005 | Sysmon 1 | Persistence that survives reboots |
| CloudTrail logging stopped | T1562.008 | CloudTrail | Attackers blind the logs right after getting in |
| AdministratorAccess attached | T1098 | CloudTrail | Privilege escalation or a backdoor admin user |

See [docs/coverage.md](docs/coverage.md) for the full map and the gaps.

## How it works

```
Atomic Red Team / AWS CLI  →  Sysmon / CloudTrail  →  Splunk or Elastic  (live alerts)
                                      │
                                      └→ exported JSON → detectionlab.scan  (replay offline)

rules/*.yml + tests/fixtures/  →  pytest in CI  →  can't merge a rule that misses or over-fires
```

## Results

**Tests (synthetic events):** 6 rules, 25 fixtures (12 attack, 13 normal), 51 tests passing. Every rule fires on all of its attack events and none of its normal ones.

To check the tests can actually fail, I broke two rules on purpose: removing the Defender exclusion from the LSASS rule made the `defender_scan` fixture fail as a false positive, and dropping the `-e` short flag made the PowerShell rule miss `short_e_flag`. Both were caught.

**Lab results (live runs):** fill this in as each Atomic Red Team or AWS test is run.

| Date | Test | Rule fired? | Time to alert | False positives seen | Notes |
| --- | --- | --- | --- | --- | --- |
| | T1059.001 #1 | | | | |
| | T1003.001 | | | | |
| | T1053.005 | | | | |
| | T1204.002 | | | | |
| | AWS StopLogging | | | | |
| | AWS AttachUserPolicy (Admin) | | | | |

## Engineering decisions

- **Every rule ships with tests.** CI requires at least one attack and one normal-activity fixture per rule, valid Sigma (checked with pySigma), ATT&CK tags and documented false positives.
- **Tuning is visible.** The LSASS rule excludes Microsoft Defender, which scans LSASS with the same access rights credential dumpers use. That exclusion has its own fixture, so removing it breaks the build.
- **Failed attempts don't alert.** The AWS rules ignore events with an `errorCode`: a denied `StopLogging` is interesting for hunting but isn't an incident, and including it would double the noise.
- **Precision over recall for noisy events.** Scheduled task creation is common, so that rule only fires when the task runs a shell or something in a user-writable folder.
- **A small evaluator instead of a full SIEM in CI.** `matcher.py` implements the common core of Sigma and has its own unit tests. Real SIEM queries come from `sigma-cli`, so the same rule file drives both.

## Security and safety

- Attack simulations only run on a dedicated VM (rolled back to a clean snapshot) and a separate sandbox AWS account.
- All fixtures are synthetic: documentation IP ranges (`198.51.100.0/24`, `203.0.113.0/24`) and a placeholder AWS account ID.
- No credentials, logs from real systems or customer data are stored in this repo.

## At 10,000× the volume

At enterprise scale the rules would run in the SIEM or a streaming pipeline (Kinesis or Kafka into a rules engine), not a Python replay. What carries over is the workflow: rules as code, fixtures as evidence, and CI as the gate. The next steps would be alert latency tracking, per-rule alert volume and false-positive rate dashboards, and suppression lists managed in code review rather than in the SIEM UI.

## Run it yourself

```bash
git clone https://github.com/SincerelyBrittany/my-first-detection-lab.git
cd my-first-detection-lab
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                                      # run every rule against its fixtures
python -m detectionlab.scan events.jsonl    # replay your own exported logs
python -m scripts.coverage                  # regenerate docs/coverage.md
```

## Adding a rule

1. Write `rules/<platform>/<name>.yml` in Sigma format with ATT&CK tags and `falsepositives`.
2. Add `tests/fixtures/<name>/malicious/*.json` and `tests/fixtures/<name>/benign/*.json`.
3. Run `pytest` and `python -m scripts.coverage`, then commit both.

## Failure log

| Date | What broke | How I triaged it | What I changed |
| --- | --- | --- | --- |

## What's next

- Run every Atomic test in the live lab and fill in **Lab results**
- One full incident write-up: an AWS sandbox intrusion from first API call to containment
- Rules from the "Not covered yet" list in [docs/coverage.md](docs/coverage.md)

---

Built by [Sincerely Brittany](https://sincerelybrittany.com) · [LinkedIn](https://www.linkedin.com/in/sincerelybrittany/)
