# SOC Triage Report

**Generated:** 2026-06-27 02:43:25  
**Window:** last 24 hours  
**Unique attacker IPs:** 7  
**By severity:** 0 critical, 1 high, 2 medium, 4 low  
**Successful logins:** none (all brute-force attempts failed)  

## Ranked alerts

| Severity | Verdict | IP | Country | ISP | Fails | Abuse | Reports | VT mal | Login |
|---|---|---|---|---|---|---|---|---|---|
| high | true positive | 45.142.193.166 | NL | Limited Network LTD | 30 | 100 | 1152 | 9 | no |
| medium | true positive | 52.140.102.59 | IN | Microsoft Corporation | 26 | 17 | 33 | 6 | no |
| medium | true positive | 20.219.16.34 | IN | Microsoft Corporation | 24 | 14 | 29 | 1 | no |
| low | false positive | 146.70.147.101 | US | M247 Miami Infrastructure | 15 | 31 | 7 | 0 | no |
| low | false positive | 20.219.16.35 | IN | Microsoft Corporation | 11 | 17 | 34 | 0 | no |
| low | false positive | 20.237.156.85 | US | Microsoft Corporation | 92 | 2 | 1 | 1 | no |
| low | false positive | 20.124.92.241 | US | Microsoft Corporation | 11 | 2 | 1 | 0 | no |

## Reasoning

- **45.142.193.166** (high / true positive): This is a true positive as there are 30 failed login attempts in an hour from an IP with a 100% AbuseIPDB confidence score and multiple VirusTotal flags. The severity is high because it indicates an active brute-force attack from a highly malicious IP, despite no successful login occurring yet.
- **52.140.102.59** (medium / true positive): This is a true positive as the source IP is flagged by multiple security vendors as malicious, indicating a genuine threat actor. The severity is medium because it is a confirmed brute-force attempt from a suspicious IP. However, the immediate impact is reduced due to the low number of failed attempts and the absence of any successful logins.
- **20.219.16.34** (medium / true positive): This is a true positive. The IP generated 24 failed login attempts in an hour and was flagged by VirusTotal as malicious/suspicious, indicating an active brute-force attack. The severity is medium as there has been no successful login from this IP, preventing immediate compromise, but the activity warrants further investigation and blocking.
- **146.70.147.101** (low / false positive): The alert shows a low number of failed login attempts (15 in one hour) from an IP with a low AbuseIPDB confidence score and no malicious flags on VirusTotal. Additionally, there were no successful logins associated with this activity. This indicates it is likely automated scanning or background noise rather than a targeted or effective brute-force attack requiring immediate human intervention.
- **20.219.16.35** (low / false positive): The alert shows only 11 failed login attempts in an hour, which is a low volume for a serious brute-force. Threat intelligence scores from AbuseIPDB and VirusTotal are also very low, and crucially, there was no successful login from this IP. This suggests the attempts were either benign, unsuccessful, or not persistent enough to be considered a high-priority threat.
- **20.237.156.85** (low / false positive): The alert, showing 92 failed login attempts from a data center IP, is likely generic internet scanning noise rather than a targeted attack. This is supported by the extremely low threat intelligence scores (AbuseIPDB 2/100, VirusTotal 1 vendor) and the critical absence of any successful logins. Therefore, it is classified as a false positive with low severity.
- **20.124.92.241** (low / false positive): The alert shows only 11 failed login attempts within an hour from an IP with very low reputation scores from AbuseIPDB and VirusTotal. There was no successful login from this IP. These factors combined indicate a very low likelihood of a targeted or sophisticated attack, and it's more likely to be noise or a minor scanning attempt.
