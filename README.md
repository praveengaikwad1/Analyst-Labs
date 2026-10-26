# Analyst Labs

Hands-on security projects built to practice the full workflow of a security analyst: discover, investigate, remediate, and document — the way it's actually done on the job, not just in theory.

Each project below is self-contained, with its own write-up, evidence, and findings.

## Projects

### ✅ [AWS S3 Misconfiguration Audit](./aws-s3-misconfiguration-audit)
Simulated a cloud security audit across four S3 buckets, each representing a distinct real-world misconfiguration pattern (public bucket policy, public ACL, overly broad "authenticated" policy). Proved each exposure was exploitable via browser and `curl`, investigated an unexpected result using AWS CLI, cross-verified a finding against official AWS documentation, then remediated and re-verified every issue.

**Tools:** AWS Console, AWS CLI, `curl`

---

### ✅ [Network Threat Hunting Lab](./Network-threat-hunting-lab)
Built an isolated two-VM lab (Suricata + Zeek) and ran two real attack scenarios — a TCP port scan and a bash reverse shell — against it. Discovered the default Suricata ruleset missed both, wrote and deployed custom detection rules to close each gap, then cross-validated every finding using Zeek's independent connection metadata. Includes a documented example of signature-based detection failing on a reverse shell that was still visible through behavioural/connection-duration analysis alone.

**Tools:** Suricata, Zeek, VirtualBox (Internal Network), Kali Linux, `nmap`, `netcat`

---

### ✅ [Active Directory Attack & Detection Lab — Kerberoasting](./active-directory-kerberoasting-lab)
Built a Windows Server 2025 domain, performed a Kerberoasting attack (MITRE ATT&CK T1558.003) from Kali with Impacket, and built the Splunk detection for it against Sysmon and Windows Security telemetry. Surfaced two findings only visible by running the attack: Server 2025's default RC4 deprecation blocked the attack at the protocol level, and under default audit settings the blocked attempt generated no log at all — a detection gap closed by enabling failure auditing and confirmed with a targeted SPL search.

**Tools:** Windows Server 2025, Active Directory, Splunk, Sysmon, Impacket, Kali Linux

---

### 🔧 SOC Automation Lab — *planned*
Automated incident response pipeline: detection in Wazuh triggers enrichment via VirusTotal through Shuffle (SOAR), with case creation in TheHive.

**Tools:** Wazuh, Shuffle, TheHive, VirusTotal API

## Background

Built while transitioning into cybersecurity, backed by Google Cybersecurity certification and ISC2 Certified in Cybersecurity coursework (all domains complete; exam pending). Each project follows the same standard: don't just configure something — break it, prove it's broken, investigate root cause, fix it, and prove the fix works.
