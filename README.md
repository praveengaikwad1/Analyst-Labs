\# Analyst Labs



Hands-on security projects built to practice the full workflow of a security analyst: discover, investigate, remediate, and document — the way it's actually done on the job, not just in theory.



Each project below is self-contained, with its own write-up, evidence, and findings.



\## Projects



\### ✅ \[AWS S3 Misconfiguration Audit](./aws-s3-misconfiguration-audit)

Simulated a cloud security audit across four S3 buckets, each representing a distinct real-world misconfiguration pattern (public bucket policy, public ACL, overly broad "authenticated" policy). Proved each exposure was exploitable via browser and `curl`, investigated an unexpected result using AWS CLI, cross-verified a finding against official AWS documentation, then remediated and re-verified every issue.



\*\*Tools:\*\* AWS Console, AWS CLI, `curl`



\---



\### ✅ \[Network Threat Hunting Lab](./Network-threat-hunting-lab)

Built an isolated two-VM lab (Suricata + Zeek) and ran two real attack scenarios — a TCP port scan and a bash reverse shell — against it. Discovered the default Suricata ruleset missed both, wrote and deployed custom detection rules to close each gap, then cross-validated every finding using Zeek's independent connection metadata. Includes a documented example of signature-based detection failing on a reverse shell that was still visible through behavioral/connection-duration analysis alone.



\*\*Tools:\*\* Suricata, Zeek, VirtualBox (Internal Network), Kali Linux, `nmap`, `netcat`



\---



\### 🔧 Active Directory Attack \& Detection Lab — \*in progress\*

Multi-VM Active Directory environment for practicing common attack techniques (Kerberoasting, Pass-the-Hash, lateral movement) and building corresponding Splunk detections against Sysmon telemetry, mapped to MITRE ATT\&CK.



\*\*Tools:\*\* Sysmon, Splunk, Active Directory, Windows Server



\---



\### 🔧 SOC Automation Lab — \*planned\*

Automated incident response pipeline: detection in Wazuh triggers enrichment via VirusTotal through Shuffle (SOAR), with case creation in TheHive.



\*\*Tools:\*\* Wazuh, Shuffle, TheHive, VirusTotal API



\## Background



Built while transitioning into cybersecurity, backed by ISC2 Certified in Cybersecurity and Google Cybersecurity certifications. Each project follows the same standard: don't just configure something — break it, prove it's broken, investigate root cause, fix it, and prove the fix works.

