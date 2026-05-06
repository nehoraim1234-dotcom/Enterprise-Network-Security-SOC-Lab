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

