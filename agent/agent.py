"""
SOC Triage Agent — Step 1: pull brute-force login alerts from Azure Log Analytics.

This module connects to a Microsoft Sentinel / Log Analytics workspace, looks for
Windows "failed logon" events (Event ID 4625), and flags any source IP that failed
to sign in more than 10 times within a single hour over the last 24 hours.
"""

import os
import json
import time
from datetime import timedelta
from enum import Enum
from pathlib import Path

import requests                                      # simple HTTP client for the threat-intel APIs
from pydantic import BaseModel                       # describes the structured output we want back
from dotenv import load_dotenv                       # reads KEY=value pairs from the .env file
from google import genai                             # the Google Gen AI SDK (Gemini)
from google.genai import types                       # request-config helpers for the SDK
from azure.identity import DefaultAzureCredential    # reuses your `az login` sign-in automatically
from azure.monitor.query import LogsQueryClient, LogsQueryStatus  # runs KQL against the workspace


# The .env file lives in the repo root, one level above this agent/ folder. Resolving
# it from __file__ means the script finds it no matter which directory you run it from.
ENV_PATH = Path(__file__).resolve().parent.parent / ".env"

# --- Threat-intel API endpoints ---
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# VirusTotal's free tier allows only 4 lookups per minute. We pause this many seconds
# between distinct IP lookups so a batch of alerts doesn't trip the rate limit (HTTP 429).
# Set it to 0 if you move to a paid key.
REQUEST_DELAY_SECONDS = 15

# Which Gemini model performs the triage classification.
GEMINI_MODEL = "gemini-2.5-flash"

# Deterministic-rule threshold: an AbuseIPDB score at or above this counts as "high abuse".
HIGH_ABUSE_THRESHOLD = 50


# The KQL query we send to the workspace:
#   1. Keep only Windows failed-logon events (EventID 4625).
#   2. Count failures, grouped by source IP AND per 1-hour time bucket.
#   3. Keep only the noisy buckets: more than 10 failures in that hour (likely brute force).
#   4. Sort so the worst offenders show up first.
BRUTE_FORCE_QUERY = """
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 1h)
| where FailedAttempts > 10
| order by FailedAttempts desc
"""


def get_brute_force_alerts():
    """Query Log Analytics and return a list of brute-force alert dicts.

    Each alert looks like:
        {"ip_address": "1.2.3.4", "failed_attempts": 57, "time_generated": <datetime>}
    """
    # --- 1. Load configuration from the .env file ---
    load_dotenv(ENV_PATH)                                     # pulls .env values into the environment
    workspace_id = os.getenv("AZURE_WORKSPACE_ID")    # the Log Analytics workspace GUID
    if not workspace_id:
        raise RuntimeError("AZURE_WORKSPACE_ID is not set — check your .env file.")

    # --- 2. Authenticate and build the query client ---
    # DefaultAzureCredential tries several auth methods in order; for local dev it
    # picks up the account you signed in with via `az login`.
    credential = DefaultAzureCredential()
    client = LogsQueryClient(credential)

    # --- 3. Run the query over the last 24 hours ---
    # `timespan` limits results to that window, so we don't need a time filter in the KQL.
    response = client.query_workspace(
        workspace_id=workspace_id,
        query=BRUTE_FORCE_QUERY,
        timespan=timedelta(hours=24),
    )

    # --- 4. Read the result tables (handle a partial or successful response) ---
    if response.status == LogsQueryStatus.SUCCESS:
        tables = response.tables                      # normal case: full results
    else:
        # PARTIAL: some data came back alongside an error — use what we got and warn.
        print(f"Warning: query returned partial results: {response.partial_error}")
        tables = response.partial_data

    if not tables:
        return []                                     # query ran fine but matched nothing

    # We only run one statement, so there is a single result table.
    table = tables[0]
    columns = table.columns                           # e.g. ["IpAddress", "TimeGenerated", "FailedAttempts"]

    # --- 5. Turn each row into a simple alert dict ---
    alerts = []
    for row in table.rows:
        record = dict(zip(columns, row))              # pair each column name with this row's value
        alerts.append({
            "ip_address": record.get("IpAddress"),
            "failed_attempts": record.get("FailedAttempts"),
            "time_generated": record.get("TimeGenerated"),  # which 1-hour bucket this count covers
        })

    return alerts


# ---------------------------------------------------------------------------
# Enrichment: for each alert IP, gather external reputation + internal context.
# ---------------------------------------------------------------------------

def check_abuseipdb(ip, api_key):
    """Look up an IP's reputation on AbuseIPDB. Returns a small dict (or an error note)."""
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},  # count reports from the last 90 days
            timeout=15,
        )
        resp.raise_for_status()                       # turn an HTTP 4xx/5xx into an exception
        data = resp.json()["data"]                    # the useful fields live under "data"
        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),  # 0-100 "how abusive" score
            "totalReports": data.get("totalReports"),                  # how many users reported it
            "countryCode": data.get("countryCode"),
            "isp": data.get("isp"),
            "usageType": data.get("usageType"),                        # e.g. "Data Center/Web Hosting"
        }
    except requests.RequestException as e:
        return {"error": str(e)}                      # network/HTTP problem -> record it, don't crash


def check_virustotal(ip, api_key):
    """Look up an IP on VirusTotal. Returns its last_analysis_stats (or an error note)."""
    try:
        resp = requests.get(
            VIRUSTOTAL_URL.format(ip=ip),
            headers={"x-apikey": api_key},
            timeout=15,
        )
        resp.raise_for_status()
        attributes = resp.json()["data"]["attributes"]
        # last_analysis_stats counts how many AV vendors put the IP in each bucket
        # (malicious / suspicious / harmless / undetected / timeout).
        return attributes.get("last_analysis_stats", {})
    except requests.RequestException as e:
        return {"error": str(e)}


def count_successful_logins(ip, client, workspace_id):
    """Check Log Analytics for SUCCESSFUL logins (EventID 4624) from this IP in the last 24h."""
    # The IP comes from our own SecurityEvent data, so it is safe to embed in the query.
    query = f"""
    SecurityEvent
    | where EventID == 4624
    | where IpAddress == "{ip}"
    | summarize SuccessfulLogins = count(), Accounts = make_set(Account, 10)
    """
    response = client.query_workspace(
        workspace_id=workspace_id,
        query=query,
        timespan=timedelta(hours=24),
    )
    # A summarize without a "by" clause always returns one row (count 0 if nothing matched).
    tables = response.tables if response.status == LogsQueryStatus.SUCCESS else response.partial_data
    if not tables or not tables[0].rows:
        return {"successful_logins": 0, "accounts": []}
    record = dict(zip(tables[0].columns, tables[0].rows[0]))
    return {
        "successful_logins": record.get("SuccessfulLogins", 0),
        "accounts": record.get("Accounts", []),       # which account(s) the IP logged into, if any
    }


def enrich_alerts(alerts):
    """Attach a combined `enrichment` dict (AbuseIPDB + VirusTotal + login check) to each alert."""
    # --- Load API keys once; a blank key means we skip that provider ---
    load_dotenv(ENV_PATH)
    abuseipdb_key = os.getenv("ABUSEIPDB_KEY")
    virustotal_key = os.getenv("VIRUSTOTAL_KEY")
    workspace_id = os.getenv("AZURE_WORKSPACE_ID")

    # One Azure client reused for every follow-up login query.
    client = LogsQueryClient(DefaultAzureCredential())

    # Cache enrichment per IP so a repeated IP isn't looked up (or rate-limited) twice.
    cache = {}
    first_lookup = True

    for alert in alerts:
        ip = alert["ip_address"]

        if ip not in cache:
            # Space out external calls to respect VirusTotal's 4-per-minute free-tier limit.
            if not first_lookup and virustotal_key:
                time.sleep(REQUEST_DELAY_SECONDS)
            first_lookup = False

            cache[ip] = {
                # 1. AbuseIPDB reputation (None if the key is blank)
                "abuseipdb": check_abuseipdb(ip, abuseipdb_key) if abuseipdb_key else None,
                # 2. VirusTotal vendor verdicts (None if the key is blank)
                "virustotal": check_virustotal(ip, virustotal_key) if virustotal_key else None,
                # 3. Did this IP actually succeed in logging in? (same workspace, EventID 4624)
                "successful_logins": count_successful_logins(ip, client, workspace_id),
            }

        alert["enrichment"] = cache[ip]                # attach the (shared) enrichment to this alert

    return alerts


# ---------------------------------------------------------------------------
# Decision step: ask Gemini to classify the alert, then apply override rules.
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    """Is this a real threat, or just noise?"""
    TRUE_POSITIVE = "true positive"
    FALSE_POSITIVE = "false positive"


class Severity(str, Enum):
    """How urgent is it?"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TriageDecision(BaseModel):
    """The exact JSON shape we force Gemini to return (structured output)."""
    verdict: Verdict
    severity: Severity
    explanation: str        # 2-3 sentences of reasoning


def classify_alert(alert):
    """Ask Gemini to classify one enriched alert, then apply deterministic override rules.

    Returns a dict with the facts, the model's RAW verdict, and the FINAL verdict
    after our rules — so the caller can see exactly where the two differ.
    """
    load_dotenv(ENV_PATH)
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not set - check your .env file.")

    # --- 1. Flatten the enriched alert into the handful of facts we send the model ---
    e = alert.get("enrichment", {})
    ab = e.get("abuseipdb") or {}            # {} if AbuseIPDB was skipped or errored
    vt = e.get("virustotal") or {}
    sl = e.get("successful_logins") or {}

    abuse_score = ab.get("abuseConfidenceScore")
    abuse_reports = ab.get("totalReports")
    vt_malicious = vt.get("malicious", 0)
    vt_suspicious = vt.get("suspicious", 0)
    country = ab.get("countryCode")
    isp = ab.get("isp")
    usage_type = ab.get("usageType")
    successful_login = sl.get("successful_logins", 0) > 0   # True if any 4624 from this IP

    # --- 2. Build the prompt: only the facts, plus the decision we want ---
    prompt = f"""You are a SOC (Security Operations Center) triage analyst.
Classify this brute-force login alert based ONLY on the facts below.

Facts:
- Source IP: {alert['ip_address']}
- Failed login attempts in 1 hour: {alert['failed_attempts']}
- AbuseIPDB confidence score: {abuse_score}/100 ({abuse_reports} community reports)
- VirusTotal: {vt_malicious} vendors flagged it malicious, {vt_suspicious} suspicious
- Country: {country}
- ISP: {isp}
- Usage type: {usage_type}
- Successful login (Windows EventID 4624) from this IP: {"YES" if successful_login else "no"}

Return:
- verdict: "true positive" if this is a real threat worth an analyst's time, else "false positive"
- severity: low, medium, high, or critical
- explanation: 2-3 sentences justifying the verdict and severity
"""

    # --- 3. Call Gemini, forcing a JSON response that matches our TriageDecision schema ---
    client = genai.Client(api_key=api_key)
    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",     # ask for JSON, not free text...
            response_schema=TriageDecision,            # ...and force it to match our schema
        ),
    )

    # response.parsed is already a validated TriageDecision; fall back to manual parse if needed.
    decision = response.parsed or TriageDecision(**json.loads(response.text))
    model_verdict = decision.verdict.value
    model_severity = decision.severity.value
    explanation = decision.explanation

    # --- 4. Deterministic override rules (these WIN over the model) ---
    final_verdict = model_verdict
    final_severity = model_severity
    override_reason = None

    # Rule: if the attacker actually got in (successful login) from a high-abuse IP,
    # it is a critical true positive no matter what the model concluded.
    if successful_login and abuse_score is not None and abuse_score >= HIGH_ABUSE_THRESHOLD:
        final_verdict = "true positive"
        final_severity = "critical"
        override_reason = (f"successful login from IP with abuse score "
                           f"{abuse_score} >= {HIGH_ABUSE_THRESHOLD} -> forced critical")

    # --- 5. Hand back model vs. final so the caller can compare them ---
    return {
        "ip_address": alert["ip_address"],
        "facts": {
            "failed_attempts": alert["failed_attempts"],
            "abuse_score": abuse_score,
            "abuse_reports": abuse_reports,
            "vt_malicious": vt_malicious,
            "vt_suspicious": vt_suspicious,
            "country": country,
            "isp": isp,
            "usage_type": usage_type,
            "successful_login": successful_login,
        },
        "model": {"verdict": model_verdict, "severity": model_severity, "explanation": explanation},
        "final": {"verdict": final_verdict, "severity": final_severity},
        "override_reason": override_reason,
    }


def print_decision(result):
    """Print one classification: the model's RAW verdict vs. the FINAL post-rule verdict."""
    f = result["facts"]
    m = result["model"]
    fin = result["final"]
    print(f"IP {result['ip_address']}")
    print(f"   Facts  : {f['failed_attempts']} fails, abuse {f['abuse_score']}/100 "
          f"({f['abuse_reports']} reports), VT {f['vt_malicious']} mal/{f['vt_suspicious']} susp, "
          f"{f['country']}, {f['isp']}, login={'YES' if f['successful_login'] else 'no'}")
    print(f"   Model  : {m['verdict']} / {m['severity']}")      # what Gemini said on its own
    print(f"   Reason : {m['explanation']}")
    print(f"   Final  : {fin['verdict']} / {fin['severity']}")  # after deterministic rules
    if result["override_reason"]:
        print(f"   Rule   : {result['override_reason']}")
    # Call it out loudly when the rules actually changed the model's answer.
    if (m['verdict'], m['severity']) != (fin['verdict'], fin['severity']):
        print("   *** RULES OVERRODE THE MODEL ***")
    print()


# --- Quick manual test: run `python agent/agent.py` to classify the alerts ---
if __name__ == "__main__":
    # Pull real alerts and enrich them (this takes ~90s due to VirusTotal throttling).
    alerts = enrich_alerts(get_brute_force_alerts())

    print("=== Gemini triage on real alerts (one per unique IP) ===\n")
    seen = set()
    for alert in alerts:
        if alert["ip_address"] in seen:
            continue                         # the facts are per-IP, so classify each IP once
        seen.add(alert["ip_address"])
        print_decision(classify_alert(alert))

    # None of the real attackers actually logged in, so the override rule never fires above.
    # This synthetic alert is deliberately BORDERLINE — only a moderate abuse score and ZERO
    # VirusTotal hits, so Gemini may rate it medium/high — but it had a successful login,
    # which trips our rule and forces CRITICAL. That makes the override visible.
    print("=== Synthetic case: successful login from a high-abuse IP (demonstrates override) ===\n")
    synthetic_alert = {
        "ip_address": "203.0.113.66",        # RFC 5737 TEST-NET address, safe placeholder
        "failed_attempts": 11,               # barely over the alerting threshold
        "time_generated": "(synthetic)",
        "enrichment": {
            # Looks fairly benign to a model — reputable cloud provider, ZERO VirusTotal
            # hits, abuse score right at the threshold, ordinary username. A model may well
            # rate this only medium/high. But there was a successful login, which our rule
            # treats as critical regardless. This is the "model under-rates it" case.
            "abuseipdb": {"abuseConfidenceScore": 50, "totalReports": 6,
                          "countryCode": "US", "isp": "Amazon.com, Inc.",
                          "usageType": "Data Center/Web Hosting/Transit"},
            "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 65},
            "successful_logins": {"successful_logins": 1, "accounts": ["jdoe"]},
        },
    }
    print_decision(classify_alert(synthetic_alert))
