# Enterprise-Attack-Detection-Lab-Entra-ID-Splunk-Kali-Linux
Built a SOC detection lab using Entra ID Splunk and Kali Linux to simulate and detect attacker behavior across identity and network systems. Configured Conditional Access and Identity Protection policies generated real attack traffic with nmap and Hydra and wrote five custom Splunk detections mapped to MITRE ATT&amp;CK 
Overview

I built a home-lab SOC project that simulates a small enterprise environment to practice and demonstrate detection engineering across both identity and network attack surfaces. The lab combines Microsoft Entra ID for cloud identity, Splunk as the SIEM, and a Kali Linux attacker box generating real reconnaissance and credential-attack traffic against a Linux victim host. I wrote custom SPL detections, a SOC dashboard, and a full incident-response playbook around the telemetry it produces.

The goal wasn’t just to run tools — it was to build the full pipeline a SOC analyst or detection engineer actually works in: generate realistic attacker behavior, get it into a SIEM correctly, write detections that map to MITRE ATT&CK, and practice the triage/containment workflow end to end.

Architecture
The lab has four pieces on an isolated host-only network so nothing touches my real LAN:

Microsoft Entra ID (free M365 developer tenant) — identity provider generating sign-in and audit logs
Splunk Enterprise (free dev license) — central SIEM ingesting both identity and host telemetry
Kali Linux — attacker VM running nmap, a brute-force simulation, and Atomic Red Team
Ubuntu victim VM — running SSH and a web service, forwarding logs via a Splunk Universal Forwarder

Entra ID logs reach Splunk through the Splunk Add-on for Microsoft Cloud Services, authenticated against an Azure App Registration with AuditLog.Read.All and Reports.Read.All Graph permissions. Victim host logs (auth.log, ufw.log, syslog) are forwarded over the standard Splunk forwarder port 9997.

Identity side — Entra ID

I stood up a developer tenant, created a handful of test users, and enabled the Entra ID P2 features: Conditional Access and Identity Protection. Specifically I configured:

A Conditional Access policy blocking legacy authentication protocols
A Conditional Access policy requiring MFA for all users
Identity Protection sign-in risk and user risk policies

These generate clean, labeled risk signals — riskLevelDuringSignIn, conditionalAccessStatus, status.errorCode — which are the fields my detections actually key off. I deliberately failed logins and signed in from varied IPs to produce realistic brute-force and location-anomaly data for Splunk to catch.

Network side — Kali reconnaissance

Everything here runs only against my own lab victim on the host-only network (192.168.56.0/24) — never anything I don’t own.

I built a recon script that runs a layered nmap sweep:

bash
nmap -sn 192.168.56.0/24                           # host discovery
sudo nmap -sS -T4 192.168.56.20                     # top-1000 SYN scan
sudo nmap -sS -p- -T4 192.168.56.20                 # full 65535-port scan
nmap -sV -p22,80,443 192.168.56.20                  # service/version detection
sudo nmap -sU --top-ports 50 192.168.56.20          # UDP scan

For the credential-attack side, I ran Hydra against a throwaway lab-only account to generate realistic Failed password log noise in auth.log:

bash
hydra -l labtest -P rockyou-sample.txt ssh://192.168.56.20 -t 4

I mapped everything to ATT&CK: port scanning → T1046 (Network Service Discovery), the brute force → T1110.001 (Password Guessing), service enumeration → T1592.

Detection engineering

This is the core of the project — five SPL detections, each tuned against real telemetry I generated myself rather than sample data:

1. Port scan detection (T1046) — flags a source IP touching 15+ distinct destination ports on the victim within a 60-second window, mostly resulting in blocked firewall actions. Severity scales with port count (medium at 15+, high at 50+, critical at 100+).

2. SSH brute force (T1110.001) — 5+ failed SSH logins for the same user/source within 5 minutes, using a regex extraction against auth.log. I also wrote a companion transaction-based search that specifically flags brute force followed by a successful login — the highest-priority case.

3. Entra ID impossible travel (T1078.004) — same user signing in successfully from two geographically distant IPs within a window too short for real travel, using iplocation and streamstats to compare consecutive sign-ins per user.

4. Entra ID risky sign-in (T1110 / T1078) — fires on riskLevelDuringSignIn=high events or repeated Conditional Access denials, binned in 10-minute windows.

5. Correlated recon-to-bruteforce detection — the one I’m most proud of. It joins the port-scan and brute-force detections on source IP using a transaction within a 30-minute window, so it only fires when the same attacker scanned the host and then tried to log in — turning two noisy, individually low-confidence alerts into one high-confidence “this is a real attack” signal.

I also built a Splunk dashboard (soc_overview_dashboard.xml) with panels for port-scan volume over time, top brute-force sources, a pie chart of Entra sign-ins by risk level, and a live table of fired alerts — basically a working SOC analyst landing page.


