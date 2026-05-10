### Phase 2: Active Directory Hardening & Identity Isolation
Design Objectives: Breaking the Attack Chain
This phase transitions the Active Directory environment from a flat, permissive state to a Zero-Trust Baseline. The primary objective is to disrupt the adversary's lifecycle—specifically Credential Harvesting and Lateral Movement—by enforcing strict trust boundaries and eliminating legacy attack vectors.

Strategic Enforcement Pillars:
Identity Tiering (LSASS Protection): Logical isolation of administrative tokens to prevent Tier 0 credential exposure on high-risk Tier 2 assets.

Protocol Eradication: Migration to a Kerberos-only environment by disabling NTLM, LLMNR, and NetBIOS, neutralizing Relay and Poisoning vectors.

Execution Control (AppLocker): Kernel-level binary verification using digital signatures to block Living off the Land (LotL) tactics.

Telemetry Augmentation: Transformation of endpoints into high-fidelity sensors via Script Block Logging and Process Command-Line Auditing.

Identity Segmentation: Tiered Administration
Objective: Mathematically eliminate the risk of Domain Admin credential theft from compromised workstations.

Engineering Logic:
The architecture enforces a "Boundary of Trust" by ensuring that high-privileged identities never authenticate to lower-security assets. This prevents the LSASS (Local Security Authority Subsystem Service) process from caching Tier 0 hashes/tickets on Tier 2 endpoints.

Tier 0 OU (Root of Trust): Dedicated container for Domain Controllers and administrative identities (e.g., Admin Nehorai).

URA Enforcement: Deployment of a "Deny-by-Default" User Rights Assignment GPO. This explicitly blocks Domain Admins from all logon vectors (Local, Network, RDP, Service, Batch) on workstations.

Result: An adversary achieving SYSTEM level access on a workstation will find zero high-privileged memory artifacts to harvest for Pass-the-Hash (PtH).

<br>
<br>

![Active Directory GPO Hierarchy](./images/active_directory_gpo_hierarchy.png)
`Active Directory Users and Computers > siem_soc.local > Corp > [Departments]`

Organizational Unit (OU) & Policy Architecture
Objective: To establish a granular, hierarchical structure that facilitates the systematic enforcement of the Principle of Least Privilege (PoLP) across the enterprise.

Engineering Logic:
A secure Active Directory environment requires the logical separation of assets and identities to prevent "policy bleeding"—where generic security settings accidentally grant excessive permissions. I engineered a modular OU hierarchy within the Corp container, allowing for targeted Group Policy Object (GPO) application based on the functional risk profile of each entity.

Global Security Baseline: GPOs linked at the domain root (e.g., Global_Network_Hardening) establish universal security controls for all objects, ensuring a consistent minimum security posture across the entire forest.

Departmental Hardening (HR/IT): Policies are applied at the sub-OU level to match specific user roles. The HR OU is subject to maximum Attack Surface Reduction (ASR) via execution restrictions, while the IT OU is configured for high-fidelity forensic auditing to monitor administrative activity.

Tiered Isolation (Tier0/Workstations): This structure serves as the technical foundation for the Tiered Administration Model. By segregating Tier 0 assets from workstation endpoints into dedicated OUs, we can apply mutually exclusive policies—such as LAPS for workstations and Session Security for domain controllers—to prevent credential leakage between security zones.

---

###  Basic Hardening and Attack Surface Reduction

Host-Level Hardening: UI-Layer Attack Surface Reduction (ASR)
Objective: To neutralize local reconnaissance capabilities for non-privileged users by restricting access to native system management interfaces.

Engineering Logic:
The HR department represents a significant risk surface due to the high volume of external communications. In a default environment, a compromised standard account provides an immediate platform for an adversary to perform Enumeration (e.g., whoami, net user, ipconfig). By enforcing a Deny-by-Default UI policy, we strip the adversary of these native tools, forcing them to import external binaries which are more likely to be intercepted by EDR/SIEM telemetry.

Key Security Controls:

Administrative Interface Isolation: Prohibited access to the Control Panel and PC Settings to prevent unauthorized modifications of local security configurations and network settings.

Shell Restriction (CMD/PowerShell UI): Disabled the Command Prompt and PowerShell interfaces for the HR OU. This prevents the execution of manual discovery commands and simple batch-based automation during the initial foothold phase.

Registry Integrity Protection: Explicitly disabled Regedit.exe to block unauthorized modifications to User-level registry hives (HKCU), a primary target for establishing Persistence via Run keys.

Configuration Path (GPO):
User Configuration > Policies > Administrative Templates > System
![HR Environment Hardening](./images/hr_user_environment_hardening.png)

<br>
<br>

### Kernel-Level Execution Control: Microsoft AppLocker
Objective: To implement a robust, bypass-resistant application control framework that ensures only authorized, cryptographically verified binaries can execute.

Engineering Logic:
While UI-based restrictions (GPOs) provide a necessary first layer of defense, they are easily bypassed by renaming executables or invoking them via background processes. To achieve true Attack Surface Reduction (ASR), I deployed Microsoft AppLocker. Unlike legacy "Software Restriction Policies," AppLocker operates at the OS kernel level, inspecting every execution request against a set of predefined rules before the process is allowed to initialize.

Implementation Phases:
A. Service Automation (The Enforcement Engine)
AppLocker relies on the Application Identity Service (AppIDSvc) to retrieve file metadata and verify signatures. By default, this service is not active. I engineered a GPO to force the service to Automatic start-up across the domain. This ensures that the enforcement engine is initialized during the boot sequence, leaving no window for unauthorized execution before policy application.

Publisher-Based Rule Logic (Identity vs. Path)
I discarded weak, legacy "Path" and "Hash" rules which are trivial to bypass (via renaming or file updates). Instead, I implemented Publisher Conditions.

Mechanism: This logic inspects the Digital Certificate embedded in the binary.

The "Deny" Logic: I created explicit Deny rules for the HR group targeting CMD.EXE, POWERSHELL.EXE, and REGEDT32.EXE. Because these rules target the Publisher (Microsoft Windows), even if an attacker renames CMD.EXE to CALC.EXE, the kernel will identify the cryptographic signature and block execution.

Operational Verification
The effectiveness of the kernel-level policy is demonstrated through a live execution test on a production endpoint. Any attempt to invoke a restricted binary—whether through the UI, a script, or a secondary process—is intercepted by the AppLocker driver, resulting in a system-level termination of the execution request.
<br>
<br>
![AppLocker Identity Service Automation](./images/applocker_identity_service_automation.png)
<br>
Computer Configuration \ Policies \ Windows Settings \ Security Settings \ System Services \ Application Identity
![AppLocker Publisher Deny Rules](./images/applocker_publisher_deny_rules.png)
<br>
Computer Configuration \ Policies \ Windows Settings \ Security Settings \ Application Control Policies \ AppLocker \ Executable Rules
![Endpoint AppLocker Restriction Verification](./images/endpoint_applocker_restriction_verification.png)

<br>
<br>

---

### PowerShell Deep Visibility & Process Auditing

[cite_start]**The Reason:** By default, Windows operating systems do not record process creation to conserve resources, leaving the SOC completely blind to execution tactics[cite: 57, 59].

**The Explanation:** I transformed every endpoint into an active security sensor. [cite_start]I enabled **Audit Process Creation** to generate Event ID 4688 every time an executable is launched[cite: 58]. [cite_start]Crucially, I integrated **Command Line Auditing** into these events, forcing the kernel to capture the exact arguments passed (e.g., `-ExecutionPolicy Bypass`) instead of just the binary name[cite: 66, 67, 71]. To counter obfuscation, I activated **PowerShell Script Block Logging**. [cite_start]This critical control captures the actual decoded code executed by the engine; if an attacker uses Base64 encoding, this log reveals the true malicious payload for forensic analysis[cite: 49, 50, 51, 52].

**Configuration Paths:**
* [cite_start]**Process Creation:** `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy > Detailed Tracking > Audit Process Creation > Success` [cite: 63]
* [cite_start]**Command Line Info:** `Computer Configuration > Policies > Administrative Templates > System > Audit Process Creation > Include command line in process creation events > Enabled` [cite: 72]
* [cite_start]**PowerShell Logging:** `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging > Enabled` [cite: 54]

![PowerShell Script Block Logging](./images/powershell_script_block_logging_config.png)
![Audit Process Creation Success Policy](./images/audit_process_creation_success_policy.png)
![Include Command Line in Event 4688](./images/include_command_line_in_event_4688.png)

---

### 5. Tier 0 Identity Protection & Lateral Movement Eradication

[cite_start]**The Reason:** In default environments, Domain Administrators can log on to any domain-joined workstation[cite: 79]. [cite_start]If a highly privileged account authenticates to a compromised Tier 2 endpoint, the Windows Local Security Authority Subsystem Service (LSASS) caches the user's credential material in RAM, enabling Pass-the-Hash (PtH) attacks via tools like Mimikatz[cite: 80, 81].

**The Explanation:** I engineered a centralized Defense-in-Depth perimeter using a strict "Tiered Identity" model. [cite_start]I created a dedicated named administrative identity (`Admin Nehorai`) in an isolated Tier0 OU[cite: 74, 76]. [cite_start]I then deployed a comprehensive "Deny All" User Rights Assignment GPO linked to the Workstations OU[cite: 82, 83]. [cite_start]This explicitly denies the Domain Admins group from authenticating across all fundamental logon types: Local (Type 2), Network (Type 3), Batch (Type 4), Service (Type 5), and RDP (Type 10)[cite: 85, 87, 89, 91, 93]. [cite_start]This ensures the Primary Token of a Domain Admin is never cached in workstation memory, mathematically eliminating lateral movement via stolen Tier 0 credentials[cite: 86, 95].

**Configuration Path:**
[cite_start]`Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > User Rights Assignment` [cite: 83]

![Tier 0 Privileged Segmentation](./images/tier0_privileged_segmentation.png)
![Tier 0 Logon Restrictions](./images/tier0_logon_restrictions.png)
![Deny Domain Admin Local Logon](./images/deny_domain_admin_local_logon_workstations.png)

---

### 6. Local Administrator Password Solution (LAPS)

[cite_start]**The Reason:** In standard deployments, local administrator accounts share a common password across all workstations[cite: 99]. [cite_start]Compromising one machine allows an attacker to extract the local NTLM hash and utilize Pass-the-Hash (PtH) to pivot to any other workstation in the domain[cite: 100].

[cite_start]**The Explanation:** I deployed Microsoft LAPS to automate the management of the built-in local administrator[cite: 98]. [cite_start]The GPO forces every workstation to generate a unique, randomized, and highly complex password that is securely stored within an active directory attribute[cite: 101, 103]. [cite_start]As a Defense-in-Depth measure against automated enumeration and malware worms, I renamed the default `Administrator` account (SID-500) to `emergencyIT`, causing brute-force scripts to fail immediately at the username validation phase, preserving SIEM bandwidth[cite: 107, 108, 109, 110].

**Configuration Paths:**
* [cite_start]**LAPS Enforcement:** `Computer Configuration > Policies > Administrative Templates > LAPS > Password Settings > Enabled` [cite: 101]
* [cite_start]**Rename Admin:** `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Accounts: Rename administrator account` [cite: 107]

![LAPS GPO Configuration Settings](./images/laps_gpo_configuration_settings.png)
![LAPS AD Attribute Verification](./images/laps_ad_attribute_verification.png)
![Emergency Admin Identity Hardening](./images/emergency_admin_identity_hardening.png)

---

### 7. Legacy Protocol Eradication: SMBv1 Vulnerability

[cite_start]**The Reason:** SMBv1 is a deprecated, 30-year-old protocol lacking modern encryption[cite: 111, 112]. [cite_start]It is heavily vulnerable to Remote Code Execution (RCE) flaws such as EternalBlue (MS17-010), utilized by ransomware worms like WannaCry to spread laterally without user interaction[cite: 112, 113].

**The Explanation:** I enforced a strict eradication of SMBv1. [cite_start]For Server-Side (Inbound) protection, a Group Policy preference injects a registry key into `LanmanServer\Parameters` setting `SMB1` to `0`, dismantling the listening service[cite: 115, 116]. [cite_start]For Client-Side (Outbound) protection, the `mrxsmb10` client driver startup type is permanently forced to `4` (Disabled), ensuring the workstation cannot initiate outbound connections to malicious legacy servers[cite: 117, 118]. [cite_start]A PowerShell audit confirmed execution[cite: 119].

**Configuration Paths:**
* [cite_start]**Server-Side:** `Computer Configuration > Preferences > Windows Settings > Registry > HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0` [cite: 115]
* [cite_start]**Client-Side:** `Computer Configuration > Preferences > Windows Settings > Registry > HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\mrxsmb10\Start = 4` [cite: 117]

![Disable SMBv1 Registry Hardening](./images/disable_smbv1_registry_hardening.png)
![Disable mrxsmb10 Kernel Driver](./images/disable_mrxsmb10_kernel_driver.png)
![SMBv1 Disable Audit](./images/smbv1_disable_audit.png)

---

### 8. NTLM Eradication & Kerberos Enforcement

[cite_start]**The Reason:** NTLM is a legacy authentication protocol that lacks mutual authentication[cite: 121]. [cite_start]This fundamental flaw allows attackers to easily intercept and relay credentials (NTLM Relay Attacks) to gain unauthorized access[cite: 121].

[cite_start]**The Explanation:** I secured the identity perimeter by completely disabling NTLM, forcing the environment to exclusively use Kerberos, which cryptographically verifies both client and server identities[cite: 122]. [cite_start]By setting the "Restrict NTLM: Incoming NTLM traffic" policy to "Deny all accounts", workstations are structurally hardened to reject legacy authentication attempts, effectively neutralizing Pass-the-Hash and inbound NTLM Relay attacks domain-wide[cite: 124, 126].

**Configuration Path:**
[cite_start]`Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Restrict NTLM: Incoming NTLM traffic` [cite: 124]

![Restrict Incoming NTLM Traffic Deny](./images/restrict_incoming_ntlm_traffic_deny.png)
![Restrict NTLM Authentication Policy](./images/restrict_ntlm_authentication_policy.png)

---

### 9. Network Cryptography: Bidirectional SMB Signing

[cite_start]**The Reason:** By default, Windows network communications do not require cryptographic signatures[cite: 129]. [cite_start]Adversaries exploit this to silently intercept traffic between workstations and servers, altering packets or relaying authentication handshakes (Man-in-the-Middle)[cite: 130].

[cite_start]**The Explanation:** I explicitly mandated digital signatures for both the originating traffic (Microsoft network client) and the receiving traffic (Microsoft network server)[cite: 131]. [cite_start]This establishes a two-way cryptographic trust requirement[cite: 132]. [cite_start]Every single packet must now carry a valid signature generated from the authenticated session key[cite: 133]. [cite_start]If an attacker attempts a relay attack, the connection drops immediately because they lack the cryptographic session key to sign manipulated packets[cite: 134].

**Configuration Path:**
[cite_start]`Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network client/server: Digitally sign communications (always) > Enabled` [cite: 135]

![SMB Signing Bidirectional Enforcement](./images/smb_signing_bidirectional_enforcement.png)

---

### 10. Defeating Network Poisoning: LLMNR & NBT-NS

[cite_start]**The Reason:** When primary DNS resolution fails, Windows endpoints default to broadcast protocols like Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS)[cite: 138]. [cite_start]Attackers exploit this via tools like Responder, listening for these broadcasts, spoofing the requested resource, and capturing the victim's NTLM hash when the machine attempts to authenticate[cite: 139, 140].

[cite_start]**The Explanation:** I implemented a two-pronged architectural defense to enforce strict DNS-only name resolution[cite: 141]. [cite_start]I eradicated LLMNR by deploying a GPO that explicitly turns off multicast name resolution at the system level[cite: 143]. [cite_start]Concurrently, I neutralized NBT-NS by deploying a PowerShell startup script that forcefully changes the `NetbiosOptions` registry key, unbinding the legacy broadcast protocol directly from the workstation's network interface card[cite: 146, 149]. [cite_start]Audits verified both protocols are permanently disabled[cite: 147, 148].

**Configuration Paths:**
* [cite_start]**Disable LLMNR:** `Computer Configuration > Policies > Administrative Templates > Network > DNS Client > Turn off multicast name resolution > Enabled` [cite: 144]
* [cite_start]**Disable NetBIOS (Startup Script):** `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions -Value 2` [cite: 146]

![Disable LLMNR GPO](./images/disable_llmnr_gpo.png)
![LLMNR Registry Audit Verification](./images/llmnr_registry_audit_verification.png)
![Disable NetBIOS Startup Script GPO](./images/disable_netbios_startup_script_gpo.png)
![NetBIOS Disabled Verification CLI](./images/netbios_disabled_verification_cli.png)
