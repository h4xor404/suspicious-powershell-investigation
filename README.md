# Incident Investigation Lab: Suspicious Encoded PowerShell Execution

![Role](https://img.shields.io/badge/Role-SOC%20Analyst%20/%20Detection%20Engineer-blue)
![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon%20|%20Event%204104-orange)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK-T1059.001%20|%20T1027%20|%20T1105-red)

## Executive Summary
This project documents an end-to-end endpoint intrusion investigation involving an obfuscated PowerShell download cradle. It covers endpoint telemetry configuration via Sysmon and Script Block Logging, parent-process lineage inspection, safe payload de-obfuscation via CyberChef, custom IOC extraction tooling via Python, and Detection-as-Code rule authoring in Sigma format.

---

## Investigation Flowchart