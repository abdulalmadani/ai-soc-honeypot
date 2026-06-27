"""
Failure-analysis test harness for the SOC triage agent.

Runs three synthetic alerts with KNOWN correct answers ("ground truth") through the
real agent (classify_alert) and compares the agent's verdict/severity against what it
*should* say. Each case is designed to probe a specific failure mode.

We deliberately SKIP the live enrichment (no AbuseIPDB / VirusTotal / Azure calls) and
hand-feed the enrichment values instead -- each synthetic "alert" is shaped exactly like
the output of enrich_alerts() in agent.py, so classify_alert() reads it with no changes.

Run:  python agent/failure_test.py
"""

import sys
from pathlib import Path

# Make `import agent` work no matter where this harness is launched from:
# add this file's folder (the agent/ directory) to the import path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Reuse the real agent code. classify_alert() already loads the .env from an absolute
# path (ENV_PATH in agent.py), so the Gemini key is found regardless of the working dir.
from agent import classify_alert


# ---------------------------------------------------------------------------
# Three synthetic test cases.
#
# Each "alert" mirrors the structure produced by the enrichment step:
#   enrichment.abuseipdb        -> {abuseConfidenceScore, totalReports, countryCode, isp, usageType}
#   enrichment.virustotal       -> {malicious, suspicious, harmless, ...}
#   enrichment.successful_logins-> {successful_logins, accounts}
#
# Each case also carries the GROUND TRUTH we expect and the failure mode it probes.
# Severity is given as a SET of acceptable answers (some cases allow a range).
# ---------------------------------------------------------------------------

TEST_CASES = [
    {
        "name": "CASE 1 - Rationalized breach (override case)",
        "tests": "whether the model talks itself out of a real breach",
        "alert": {
            "ip_address": "203.0.113.66",
            "failed_attempts": 11,
            "enrichment": {
                "abuseipdb": {"abuseConfidenceScore": 50, "totalReports": 6,
                              "countryCode": "US", "isp": "Amazon.com, Inc.",
                              "usageType": "Data Center/Web Hosting/Transit"},
                "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 65},
                # The attacker actually got in -- this is the decisive fact.
                "successful_logins": {"successful_logins": 1, "accounts": ["jdoe"]},
            },
        },
        "ground_truth": {
            "verdict": "true positive",
            "severities": {"critical"},          # a successful breach is critical, full stop
            "display": "true positive / critical",
        },
    },
    {
        "name": "CASE 2 - Brand-new malicious IP (clean reputation)",
        "tests": "whether the agent over-trusts a clean / empty reputation",
        "alert": {
            "ip_address": "198.51.100.23",
            "failed_attempts": 45,
            "enrichment": {
                # Score 0 with 0 reports: brand new, simply never reported YET -- not proof of safety.
                "abuseipdb": {"abuseConfidenceScore": 0, "totalReports": 0,
                              "countryCode": "RU", "isp": "Hosting Solutions Ltd",
                              "usageType": "Data Center/Web Hosting/Transit"},
                # Never analyzed before -> nothing flagged, almost everything "undetected".
                "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 62},
                "successful_logins": {"successful_logins": 0, "accounts": []},
            },
        },
        "ground_truth": {
            "verdict": "true positive",
            # Sustained brute force from hosting infra; absence of reports != absence of threat.
            "severities": {"medium", "high", "critical"},   # at least medium
            "display": "true positive / medium-or-higher",
        },
    },
    {
        "name": "CASE 3 - High-volume benign scanner",
        "tests": "whether the agent over-reacts to raw volume",
        "alert": {
            "ip_address": "192.0.2.200",
            "failed_attempts": 500,
            "enrichment": {
                # Very low reputation and a recognizable research-scanner ISP.
                "abuseipdb": {"abuseConfidenceScore": 3, "totalReports": 1,
                              "countryCode": "US", "isp": "Censys, Inc.",
                              "usageType": "Data Center/Web Hosting/Transit"},
                "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 72},
                "successful_logins": {"successful_logins": 0, "accounts": []},
            },
        },
        "ground_truth": {
            "verdict": "false positive",
            "severities": {"low"},               # huge count, but benign internet scanning noise
            "display": "false positive / low",
        },
    },
]


def run_case(case):
    """Classify one synthetic alert and compare the agent's output to ground truth."""
    result = classify_alert(case["alert"])       # real Gemini call, synthetic enrichment

    model = result["model"]                      # the model's RAW answer (before deterministic rules)
    final = result["final"]                      # the agent's FINAL answer (after override rules)
    gt = case["ground_truth"]

    # The agent "matches" when its FINAL verdict equals ground truth and its severity
    # falls within the acceptable set for this case.
    is_match = (final["verdict"] == gt["verdict"]) and (final["severity"] in gt["severities"])

    # --- Comparison block ---
    print("=" * 64)
    print(case["name"])
    print(f"Tests: {case['tests']}")
    print("-" * 64)
    print(f"  Model (raw)  : {model['verdict']} / {model['severity']}")
    print(f"  Agent (final): {final['verdict']} / {final['severity']}")
    print(f"  Ground truth : {gt['display']}")
    print(f"  Result       : {'MATCH' if is_match else 'MISMATCH'}")
    # Surface when the deterministic rule had to rescue (or change) the model's answer.
    if (model["verdict"], model["severity"]) != (final["verdict"], final["severity"]):
        print(f"  Note         : override rule changed the model's answer "
              f"({model['verdict']}/{model['severity']} -> {final['verdict']}/{final['severity']})")
    print("=" * 64)
    print()
    return is_match


if __name__ == "__main__":
    results = []
    for case in TEST_CASES:
        try:
            results.append(run_case(case))
        except Exception as exc:                 # keep going even if one Gemini call fails
            print(f"ERROR running {case['name']}: {exc}\n")
            results.append(False)

    matched = sum(results)
    print(f"SUMMARY: {matched}/{len(TEST_CASES)} cases matched ground truth.")
