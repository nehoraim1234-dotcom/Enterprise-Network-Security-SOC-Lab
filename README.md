# Enterprise-Network-Security-SOC-Lab
A comprehensive cybersecurity lab featuring network segmentation, AD hardening, and SIEM detection engineering.


## Phase 1: Infrastructure & Security Architecture

### Objective
The foundation of any resilient environment begins at the network layer. The primary objective of this phase is to dismantle the traditional "flat network" model and establish a strict **Zero Trust** architecture. By logically isolating critical infrastructure from standard user endpoints, the environment forces all network traffic through a centralized inspection and routing plane, effectively neutralizing initial access and lateral movement attempts at the perimeter.

### Key Implementations

* **Network Segmentation & Traffic Inspection:**
    Engineered a multi-homed routing architecture utilizing a pfSense firewall as the core gateway. The environment is partitioned into three distinct zones to enforce strict trust boundaries:
    * **WAN:** Controlled external connection featuring perimeter hardening against Bogon and RFC 1918 (Private) IP spoofing attacks.
    * **Servers Zone (Tier 0):** An isolated subnet (`192.168.10.0/24`) dedicated solely to the Active Directory Domain Controller and critical infrastructure.
    * **Users Zone (Tier 2):** A segregated subnet (`192.168.20.0/24`) hosting standard employee workstations.
* **Positive Security Model (Identity Protection):**
    Deployed a default-deny posture around the identity infrastructure. Network traffic from the Users Zone to the Domain Controller is explicitly whitelisted only for essential protocols (DNS, Kerberos, LDAP). Management and remote execution ports (e.g., RDP, WinRM) are permanently dropped to sever traditional lateral movement pathways.
* **Dynamic Threat Intelligence Integration:**
    Transitioned the firewall from a static rule-set to an active defense mechanism. By integrating automated, real-time threat feeds (such as Abuse.ch and Emerging Threats), the gateway autonomously identifies and drops outbound traffic destined for known Command and Control (C2) servers, breaking the cyber kill chain before data exfiltration can occur.
* **Identity & Access Management (IAM) Automation:**
    Developed a PowerShell-driven provisioning pipeline that parses HR-provided CSV files to automatically build and assign Active Directory accounts. This logic eliminates human misconfiguration, prevents privilege creep, and guarantees precise placement into authorized Organizational Units and Security Groups.




## Phase 2: Active Directory Hardening & GPO Architecture

### Objective
With a secure network foundation in place, the second phase focuses on fortifying the identity perimeter. The objective is to transform the Active Directory environment into a hardened "Fortress Domain" by implementing a Tiered Administration Model. This phase systematically eliminates the most common internal attack vectors—such as credential dumping, lateral movement, and protocol exploitation—through a granular and automated Group Policy (GPO) architecture.

### Key Implementations

* **Hierarchical GPO & OU Design:**
    Established a strictly segmented Organizational Unit (OU) structure to enforce the **Principle of Least Privilege (PoLP)**. By separating administrative accounts (Tier 0), technical staff (IT), and standard users (HR) into distinct OUs, I applied tailored security baselines that balance maximum security with operational continuity.
* **Tier 0 Lateral Movement Prevention:**
    Engineered a comprehensive "Administrative Boundary" to protect highly privileged credentials. I implemented explicit `User Rights Assignment` policies that structurally block Domain Admins from authenticating against Tier 2 workstations across all five logon types (Local, Network, RDP, Batch, and Service). This architectural constraint ensures that even if a workstation is compromised, the adversary is blocked from harvesting Tier 0 credentials.
* **Kernel-Level Application Control (AppLocker):**
    Advanced beyond basic UI restrictions to implement **AppLocker** at the OS kernel level. Utilizing cryptographic **Publisher** conditions, the system verifies the digital signature of binaries rather than easily spoofed file names. This ensures that critical tools like `CMD.EXE` and `PowerShell` are categorically denied for non-authorized users, regardless of file location or renaming attempts.
* **Credential Protection via LAPS & Account Obfuscation:**
    Deployed the **Microsoft Local Administrator Password Solution (LAPS)** to automate the rotation of unique, high-complexity passwords for the built-in SID-500 account across all endpoints. To further thwart automated enumeration and brute-force scripts, the default administrator account was renamed to `emergencyIT`, reducing SOC alert fatigue and increasing attacker frustration.
* **Legacy Protocol Eradication & Cryptographic Integrity:**
    Systematically decommissioned high-risk legacy protocols to secure the internal transport layer:
    * **NTLM Eradication:** Disabled NTLM to force strictly Kerberos-driven authentication, neutralizing NTLM Relay and Pass-the-Hash attacks.
    * **Network Poisoning Mitigation:** Disabled LLMNR and NetBIOS over TCP/IP to prevent credential theft via network poisoning tools like Responder.
    * **SMB Hardening:** Completely disabled the vulnerable SMBv1 protocol and enforced **SMB Signing** to establish bidirectional cryptographic integrity for all network communications.
* **Forensic Readiness & Endpoint Telemetry:**
    Transformed every domain asset into an active security sensor by enabling advanced auditing. This includes **Audit Process Creation** with full **Command-Line logging**, providing the SIEM with high-fidelity telemetry required to detect obfuscated scripts and Living-off-the-Land (LotL) tactics.



## Phase 3: Detection Engineering & SIEM Architecture

### Objective
The final phase focuses on operationalizing the environment by transitioning from static defense to active monitoring. [cite_start]By deploying a centralized Splunk Enterprise SIEM, I established a scalable telemetry pipeline to aggregate logs from distributed assets, enabling a structured approach to threat detection and incident readiness[cite: 174, 177].

### Key Implementations

* **Telemetry Pipeline & Data Ingestion:**
    [cite_start]Engineered a centralized ingestion architecture designed for broad visibility across key infrastructure components. [cite_start]Lightweight Splunk Universal Forwarders were deployed to Windows assets to stream Security, System, and Application event channels via encrypted TCP sockets on Port 9997[cite: 183, 184]. [cite_start]Simultaneously, the pfSense gateway was integrated to forward native Syslog telemetry over UDP Port 514, providing critical visibility into firewall blocks and network-layer anomalies[cite: 185, 186].
* **Detection Logic & Alert Optimization:**
    Developed targeted detection pipelines using Splunk Search Processing Language (SPL) to identify high-risk behaviors while reducing false positives through correlation and specific field-filtering[cite: 189, 236]. By utilizing advanced functions like multi-value indexing (`mvindex`), the system accurately parses complex event structures (e.g., Event ID 4720/4732) to map relationships between actors and targets during potential privilege escalation or persistence attempts[cite: 250, 251, 253].
* **Modular Threat Intelligence Framework:**
    Architected a scalable detection engine utilizing a centralized lookup table (`Domain_Threat_Intel_Masterlist.csv`)[cite: 262, 263]. This approach moves away from hardcoded search strings, instead using a dynamic Regex engine to match process command-line arguments against known adversary tooling patterns (e.g., Mimikatz, BloodHound)[cite: 265, 278, 282]. This modular design improves coverage and allows the SOC to update threat signatures instantly without modifying underlying detection code[cite: 272, 273].





  


  
