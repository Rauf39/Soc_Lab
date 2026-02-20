Overview

This project is my personal Security Operations Center (SOC) lab built to simulate real-world attacks and practice detection, monitoring, and investigation using SIEM, XDR, and vulnerability scanning tools.

The goal of this lab is to gain hands-on experience with:

Attack simulation

Log collection and analysis

Threat detection

Alert investigation

Vulnerability assessment

Endpoint monitoring

Lab Architecture

Components used in this lab:

SIEM: Splunk Enterprise

XDR / HIDS: Wazuh

Vulnerability Scanner: Nessus Essentials

Attacker Machine: Kali Linux

Victim Machines:

Ubuntu 22.04

Windows 10

Supporting tools and integrations:

Splunk Universal Forwarder

Sysmon (Windows logging)

auditd (Linux logging)

VirusTotal API integration

Nmap (network scanning)

Hydra (SSH brute-force simulation)

Network Layout

Example IP addresses used:

Splunk SIEM: 192.168.0.43

Wazuh Server: 192.168.0.3

Ubuntu Victim: 192.168.0.10

Windows Victim: 192.168.0.152

Kali Attacker: 192.168.0.30

Log Collection

Logs collected from endpoints include:

Windows logs

Security events

Sysmon logs

Process creation events

Account creation and modification

Privilege escalation attempts

Forwarded using:

Splunk Universal Forwarder

Wazuh Agent

Linux logs

Collected using:

auditd

Wazuh agent

Examples:

SSH login attempts

File integrity changes

Privilege escalation events

Command execution monitoring

Detection and Alerts

Custom alerts created in Splunk:

SSH brute force detection

Multiple failed login attempts

Sudo usage alerts

Suspicious activity monitoring

Example detection query:

index=* source="/var/log/auth.log" "Failed password"
| stats count by src, user
| sort -count

This allows identification of brute force attempts from attacker machines.

Attack Simulation

Attacks performed from Kali Linux:

Nmap scanning

Used to discover open ports and services:

nmap -sS -p- 192.168.0.43

Detected by SIEM and visible in logs.

SSH brute force attack

Performed using Hydra:

hydra -l root -P rockyou.txt ssh://192.168.0.43

Detected in Splunk as:

Multiple failed login attempts

Brute-force behavior

File Integrity Monitoring (FIM)

Implemented using Wazuh and Splunk.

Example detections:

Modification of system files

Creation of suspicious files

Unauthorized file changes

Example monitored files:

/etc/passwd
/usr/bin/
Vulnerability Scanning

Performed using Nessus Essentials.

Scan results included:

PostgreSQL vulnerabilities

Open ports

Security misconfigurations

Helps identify weaknesses in the environment.

VirusTotal Integration

VirusTotal API used for:

File reputation checking

Malware detection

Threat intelligence enrichment

Allows validation of suspicious files.

Wazuh Integration

Wazuh provides:

Endpoint monitoring

Threat detection

File integrity monitoring

Log analysis

Integrated with Splunk for centralized monitoring.

Skills Demonstrated

This lab demonstrates hands-on experience with:

SIEM monitoring (Splunk)

XDR / HIDS monitoring (Wazuh)

Vulnerability scanning (Nessus)

Attack simulation (Kali Linux)

Log analysis

Alert creation

Threat detection

Endpoint monitoring

Security investigation

Screenshots

See screenshots folder for:

Splunk alerts

Wazuh dashboards

Nessus scans

Attack simulations

Detection results

Future Improvements

Planned additions:

SOAR integration

Firewall monitoring

Azure Sentinel integration

Active Directory lab

Author

Rauf Mammadov
Cybersecurity Student | Security+ Certified
Aspiring SOC Analyst
