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

## 3. Telemetry and Data Ingestion Pipeline

**Why we did this:**
To ensure total visibility across heterogeneous operating systems and network appliances, a multi-protocol ingestion pipeline was engineered. This establishes the necessary data foundation before any detection logic can be applied.

![Splunk Data Ingestion Overview](images/siem_critical_alerts_dashboard.png)

**What we did and how:**
* **Windows Environment via Universal Forwarders:** Lightweight Splunk Universal Forwarders were deployed to the Windows Server and Windows 11 endpoints. The local `inputs.conf` and `outputs.conf` files were manually configured to establish encrypted Splunk-to-Splunk TCP sockets on port 9997. The forwarders are strictly configured to capture critical Security, System, and Application event channels.
* **Network Appliance via Syslog:** The FreeBSD-based pfSense gateway is configured to forward native remote Syslog telemetry over UDP port 514. This captures firewall blocks, DHCP leases, and routing events. A dedicated syslog sourcetype was assigned at the Indexer level to ensure automated field extraction.
* **SIEM Self-Auditing:** Splunk is configured to actively monitor its own underlying Kali Linux host by reading local `/var/log/` files, tracking SSH authentications and system executions.

---

## 4. Threat Detection Use Cases

### Use Case 1: LAPS Break-Glass Account Activation (Interactive Logon)

**Why we did this:**
To establish a real-time detection mechanism for any interactive authentication attempts utilizing the obfuscated local administrator account (`emergencyIT`). This account is dynamically managed by LAPS and is architecturally reserved strictly for "break-glass" scenarios, such as a complete loss of domain trust. Standard operating procedures dictate this account should never experience an interactive logon under normal conditions.

![LAPS Alert Configuration](images/emergencyit_realtime_alert_detail.png)
![LAPS Fired Alert Validation](images/laps_critical_logon_fired_alert.png)

**What we did and how:**
By specifically filtering for `Logon_Type=2` (Interactive/Physical keyboard logon), the rule is engineered to eliminate false positives originating from background services or network scans. Any successful authentication utilizing this account triggers an immediate Critical alert, indicating either an active emergency IT recovery process or a severe lateral movement compromise by an adversary.
* **Alert Configuration:** Real-time (ensuring zero-latency detection). Trigger Condition: Per-Result. Severity: Critical. Permissions: Shared in App.
* **Validation & Auditing:** To mathematically validate the detection pipeline, a physical authentication simulation was conducted on a domain-joined endpoint using the dynamic LAPS password retrieved directly from the Domain Controller's attributes. The Splunk Indexer successfully ingested the telemetry, parsed the event, and instantaneously triggered the Critical alert within the SOC dashboard.

```splunk
index="main" source="WinEventLog:Security" EventCode=4624 Account_Name="emergencyIT" Logon_Type=2
