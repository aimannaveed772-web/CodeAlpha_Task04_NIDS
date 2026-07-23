# CodeAlpha_Task04_NIDS
Network Intrusion Detection System (NIDS) simulation in Java | CodeAlpha Task 04
# Task 4: Network Intrusion Detection System (NIDS) — CodeAlpha Internship

## Overview
This repository contains a Java-based Network Intrusion Detection System (NIDS) simulation developed during the CodeAlpha Cybersecurity Internship. The system analyzes incoming network packet payloads in real-time against configurable security detection rules to identify malicious activity and automatically log security alerts.

---

## Features
* **Rule-Based Engine:** Uses Regular Expressions (Regex) to inspect packet payloads for attack signatures.
* **Threat Detection Coverage:**
  * **SQL Injection (SQLi)**
  * **Port Scanning / Reconnaissance**
  * **Directory Traversal**
  * **Denial of Service (DoS) / SYN Flood attempts**
* **Automated Alert Logging:** Outputs real-time warnings to the console and appends detailed, timestamped logs to `nids_alerts.log`.

---

## File Structure
* `IntrusionDetectionSystem.java` — Core application code containing the NIDS engine and rules.
* `nids_alerts.log` — Output log file generated upon threat detection.

---

## Technical Details
* **Language:** Java (JDK 21)
* **IDE:** Eclipse
* **Core APIs:** `java.util.regex`, Java I/O (`PrintWriter`, `FileWriter`), `java.time`
