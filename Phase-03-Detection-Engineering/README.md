Phase-03-Detection-Engineering/README.md
# Phase 3: Detection Engineering and SIEM Architecture

## 1. Executive Summary
This phase establishes the foundational infrastructure for log aggregation by facilitating the secure transmission of telemetry from distributed assets to the centralized Splunk Enterprise SIEM. The architecture is engineered to provide full-stack visibility by correlating network-layer activity with endpoint process execution.

Infrastructure Telemetry Sources
The ingestion strategy utilizes two primary transmission methodologies to ensure data integrity across the environment:

Network Gateway Telemetry (pfSense):
Log collection from the pfSense perimeter gateway is achieved via a native, agentless Syslog implementation. The firewall is configured to forward system and traffic logs over UDP Port 514. This provides critical visibility into network-layer anomalies, firewall rule violations, and NAT translations, serving as the primary source for identifying external threat vectors.

Endpoint Asset Telemetry (Windows Server & Client):
Visibility into the internal host layer is established by deploying Splunk Universal Forwarders (UF) across all Windows assets. These lightweight agents utilize a dedicated Encrypted TCP Socket on Port 9997 to stream high-fidelity event data. The configuration focuses on the Security Event Channel, specifically capturing Event ID 4688 (Process Creation) to enable the detection of unauthorized binary execution and adversary command-line activity.

Splunk Ingestion Configuration
To facilitate the reception of these telemetry streams, the Splunk Indexer was configured with dedicated listeners, ensuring proper data segregation and indexing:

TCP Receiver (Port 9997): Architected to terminate encrypted connections from Universal Forwarders, allowing for the ingestion of "cooked" data ready for immediate indexing.

UDP Listener (Port 514): Configured as a Syslog input to capture and parse asynchronous packets from the network gateway, assigning them to the netfw sourcetype for structured analysis.


---

Modular Threat Intelligence & Detection Engineering
The transition from passive log collection to active threat detection requires a structured approach to identifying adversary activity. In this phase, the SIEM architecture was enhanced by implementing a Modular Threat Intelligence Framework. This approach is superior to traditional, hardcoded detection rules because it centralizes intelligence into a single repository, allowing for rapid updates and scalable monitoring across the entire infrastructure.

The Centralized Intelligence Repository
Before the detection engine can identify a threat, it must have a reliable source of "truth" regarding what constitutes a malicious event. To achieve this, a centralized intelligence layer was developed using a dedicated repository: Domain_Threat_Intel_Masterlist.csv.


The Significance of Adversary Tooling (Red Flags)
The patterns defined in the masterlist—such as Mimikatz, Responder, Rubeus, and BloodHound—represent high-fidelity Indicators of Compromise (IoCs). In a production enterprise network, the presence of these terms in a process command line is an immediate "Red Flag" :

Credential Dumping (Mimikatz): Tools like Mimikatz are specifically engineered to extract plaintext passwords and NTLM hashes from memory (LSASS). Seeing this tool execute even a single time indicates a 100% probability of a post-exploitation phase where an attacker is attempting to escalate privileges.

Because these tools are exclusively used for exploitation or advanced penetration testing, the detection engine is tuned to treat any single occurrence as a critical security event.

![Domain Threat Intel Masterlist](./images/ioc_threat_intel_masterlist_csv.png)

Maintaining a standalone intelligence list is a critical architectural requirement in a professional SOC environment. It ensures that detection signatures are decoupled from the search logic. If a new threat emerges, the SOC analyst only needs to update the list, and all associated alerts are instantly updated without the need to modify complex SPL code. This minimizes the risk of syntax errors during a high-pressure incident and ensures that the environment remains agile against evolving attack vectors.

![Dynamic Regex Detection Engine Results](./images/dynamic_regex_detection_engine_results.png)

The following results demonstrate the system successfully identifying multiple unauthorized tool executions across the network. By correlating the Process_Command_Line with the centralized intelligence list, the engine correctly flagged executions of mimikatz.exe and responder.exe, providing the SOC with the exact timestamp, the affected host, and the user account responsible for the activity.


Identity & Access Monitoring: LAPS & Break-Glass Accounts

dentity & Access Monitoring: LAPS & Break-Glass Accounts
In a hardened Active Directory environment, "Break-Glass" accounts (such as those managed via LAPS or dedicated emergency IT accounts) are intended for use only during extreme recovery scenarios. Under normal operational conditions, these accounts should remain dormant. Monitoring these accounts is a high-fidelity detection strategy, as any logon activity involving an emergency credential is, by definition, a significant security event that requires immediate validation.

Real-Time Monitoring Configuration
To ensure zero-latency visibility, a Real-Time Alert was engineered to monitor the specific logon events associated with these privileged accounts. The detection logic focuses on successful authentications (Event ID 4624) where the target user matches the defined emergency identity. This alert is configured with a Per-Result trigger to ensure that every single logon attempt is captured and escalated, providing the SOC with an instantaneous notification of highly privileged access.

Operational Validation: Unauthorized Privileged Access
The significance of monitoring accounts like emergencyIT cannot be overstated. From an adversary's perspective, compromising a "Break-Glass" account provides near-unrestricted access to the domain infrastructure, often bypassing standard MFA or conditional access policies. Therefore, seeing this account logged in without a pre-approved change window is a critical "Red Flag" indicating a potential compromise or a severe breach of internal protocol.

![LAPS Break-Glass Alert Detail](./images/emergencyit_realtime_alert_detail.png)

![Fired Alert: LAPS Break-Glass Logon](./images/laps_critical_logon_fired_alert.png)

The following evidence confirms the system's ability to detect and visualize this activity in the SOC dashboard. Upon the simulation of a logon event for the emergencyIT account, the SIEM successfully identified the telemetry, applied the detection logic, and fired a Critical severity alert. This operational proof demonstrates that the SOC has full visibility .


Statistical Analysis & Authentication Anomalies

Statistical Analysis & Authentication Anomalies (Brute Force)
Detecting automated authentication attacks requires a transition from simple signature matching to Statistical Threshold Monitoring. While a single failed logon is often the result of a user typo, a high frequency of failures in a concentrated timeframe is a primary indicator of automated Brute Force or Password Spraying attempts.

Brute Force Detection Strategy
To identify these anomalies without generating excessive noise (False Positives), a Scheduled Alert was engineered with a defined statistical threshold. The logic monitors for Event ID 4625 (Failed Logon) and is configured to trigger only when the frequency exceeds 5 failed attempts within a 10-minute sliding window.

This threshold-based approach ensures that the SOC only receives alerts for high-fidelity anomalies. The alert is configured as a Scheduled Cron Job to run every 10 minutes, analyzing the cumulative telemetry from the Windows endpoints to identify patterns that deviate from standard human behavior.

Operational Result: Excessive Authentication Failures
The significance of this statistical monitor is proven by its ability to identify automated patterns across the domain infrastructure. By utilizing the Per-Result trigger mode, the alert provides the analyst with granular details, including the specific workstation under attack and the targeted accounts. This allows for immediate incident response actions, such as temporary account lockout or the implementation of network-level blocks on the offending IP address.

![Brute Force Alert Configuration](./images/brute_force_scheduled_alert_config.png)

![Fired Alert: Brute Force Detection](./images/splunk_brute_force_statistical_alert.png)


The following evidence illustrates the operational output of the Brute Force detection engine. Upon the breach of the 5-failure threshold, the SIEM successfully identified the anomaly and promoted the event to the SOC dashboard as a High Severity incident.


Defense Evasion & Anti-Forensics Detection

In a high-maturity security environment, any attempt to manipulate or delete audit trails is treated as a Critical event. Attackers frequently clear Windows Event Logs to hide evidence of lateral movement, credential dumping, or unauthorized configuration changes. Detecting these actions is essential for maintaining the integrity of the forensic trail.

Real-Time Alert Configuration
To ensure immediate response, a Real-Time Alert was engineered specifically targeting the clearing of security logs. The logic monitors for Event ID 1102 (Security log cleared) and Event ID 104 (System log cleared). Unlike scheduled alerts, this monitor triggers a notification the millisecond the event is indexed.

The configuration utilizes a Per-Result trigger condition. This ensures that if logs are cleared across multiple hosts simultaneously, each instance is captured as a unique incident, providing the SOC with a complete map of the attacker’s evasion attempts across the network.

![Log Clearing Alert Configuration](./images/log_clearing_realtime_alert_config.png)

![Fired Alert: Windows Log Clearing](./images/fired_alert_windows_log_clearing.png)

Operational Validation: Potential Defense Evasion Identified
The following evidence confirms the effectiveness of the real-time monitor. The SIEM successfully identified a manual log-clearing event on a production endpoint and escalated it to Critical status.


Identity Analysis & Privilege Escalation Detection

Monitoring identity-based events within Active Directory is a cornerstone of SOC operations. Attackers often seek to establish Persistence by creating new user accounts or elevating existing ones to privileged groups (e.g., Domain Admins). Detecting these changes requires more than just identifying an Event ID; it requires sophisticated data parsing to distinguish between the administrator performing the action and the account being modified.

Technical Challenge: Multi-Value Field Parsing
A significant technical hurdle when analyzing Windows Security logs—specifically Event ID 4720 (Account Creation) and Event ID 4732/4728 (Member Added to Group)—is the structure of the Account_Name field. Windows logs these as "Multivalue" fields, where the same field name is used for different entities within a single event.

The Conflict: The log contains two Account_Name entries. The first is the Actor (the Subject who performed the action), and the second is the Target (the object/user being created or changed).

The Solution: To transform this raw data into an actionable alert, I utilized the Splunk mvindex function within an eval command.

Detailed Logic Breakdown:

Indexing: Splunk stores these multiple values in an array-like structure.

eval Actor = mvindex(Account_Name, 0): This command instructs the engine to extract the value at index 0 (the first occurrence), which corresponds to the administrative account that initiated the change.

eval Target_User = mvindex(Account_Name, 1): This extracts the value at index 1 (the second occurrence), identifying the specific account that received the new permissions or was newly created.

This granular parsing ensures that the SOC analyst receives a clear narrative: "Admin X created Account Y," rather than a confusing log that lists the same field name twice.

![Advanced Identity Parsing](./images/spl_advanced_parsing_privilege_escalation.png)

![Identity Analysis Result](./images/siem_critical_alerts_dashboard)

Operational Result: Detection of Unauthorized Persistence
The effectiveness of this detection logic is demonstrated in the operational proof below. The system successfully identified a sequence of high-risk events originating from the Domain Controller (DC100).

In this scenario, the SIEM detected the creation of a new user account named backdoor, followed immediately by its addition to a privileged group. Because the SPL logic successfully separated the Actor (administrator) from the Target (backdoor), the resulting alert provides the immediate context needed for an incident response. This allows the SOC to verify if the creation of a "backdoor" account was a sanctioned administrative action or a critical indicator of compromise.
