# task-apex-planet-2
task 2


# 🛡 Apex Planet Internship — Task 2  
## *Network Security & Scanning*

---

### 👨‍💻 Intern Details
- *Name:* Dhonthula Sairam 
- *Intern ID:* APSPL251920  
- *Internship Domain:* Network Security  
- *Organization:* Apex Planet Pvt. Ltd.  
- *Task Number:* 2  
- *Task Title:* Network Security & Scanning  

---

## 🧩 Overview
This task focuses on understanding and performing *Network Scanning, **Vulnerability Assessment, **Packet Capture & Analysis, and **Firewall Configuration* using various tools available in *Kali Linux*.

The purpose is to simulate a real-world network security assessment process — discovering hosts, finding vulnerabilities, analyzing packets, and strengthening system security with firewall rules.

---

## ⚙ Tools Used

| Tool | Description |
|------|--------------|
| *Nmap* | Network mapping, service discovery, and OS detection |
| *OpenVAS / GVM* | Vulnerability scanning and reporting |
| *Tcpdump / Wireshark* | Network packet capturing and analysis |
| *iptables* | Firewall configuration and traffic filtering |

---

## 🔍 Step-by-Step Execution

### *1️⃣ Network Scanning — Nmap*
Performed a full scan on target IP: 192.168.56.101

*Command Used:*
```bash
nmap -sS -sV -A 192.168.56.101 -oN nmap-full-192.168.56.101.txt

Results:

Detected multiple open ports (22, 80, 443, etc.)

Identified services running on each port

Gathered OS information and server banners

Generated File: nmap-full-192.168.56.101.txt

2️⃣ Vulnerability Scanning — OpenVAS / GVM

OpenVAS (Greenbone Vulnerability Manager) was used to perform a deep vulnerability assessment of the target system.

Steps:

Configured target in GVM dashboard

Launched full and fast scan

Exported scan results as PDF and XML

Results Summary:

Critical vulnerabilities: outdated server version

Medium vulnerabilities: weak SSL/TLS configurations

Suggested mitigations: patch updates, service hardening, SSL improvements

Generated Files:

OpenVAS-GVM-results.pdf

report.xml

report_notes.md

3️⃣ Packet Capture & Analysis — Tcpdump / Wireshark

Captured live network traffic to analyze communication patterns.

Commands Used:

sudo tcpdump -i eth0 -c 200 -w capture.pcap


Analysis Performed:

Opened .pcap in Wireshark

Observed TCP 3-way handshakes and DNS requests

No suspicious traffic found

HTTP request headers revealed potential server information

Generated Files:

capture.pcap

packet-analysis.txt

4️⃣ Firewall Configuration — iptables

Configured firewall to control incoming and outgoing traffic.

Commands Used:

sudo iptables -L > iptables-before.txt
sudo iptables -A INPUT -p tcp --dport 22 -j DROP
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -L > iptables-after.txt
sudo iptables-save > iptables-restored.txt


Results:

Blocked SSH port (22)

Allowed HTTP traffic (80)

Verified and logged changes

Generated Files:

iptables-before.txt

iptables-after.txt

iptables-restored.txt

firewall-status.txt

📁 Files & Artifacts Summary
File	Description
nmap-full-192.168.56.101.txt	Nmap scan results
OpenVAS-GVM-results.pdf	Full vulnerability scan report
report.xml	XML export of OpenVAS scan
report_notes.md	Notes and summary of vulnerabilities
capture.pcap	Packet capture file
packet-analysis.txt	Text analysis of first 200 packets
iptables-before.txt, iptables-after.txt, iptables-restored.txt	Firewall configuration logs
firewall-status.txt	Summary of firewall rules
ss/	Screenshots of each step
🧠 Learnings & Outcomes

✅ Gained hands-on experience with:

Network mapping & port scanning

Vulnerability detection & reporting

Packet capture & inspection

Basic firewall rule creation

✅ Understood how:

Attackers identify vulnerable services

Security professionals secure systems

Network monitoring reveals hidden insights

🧾 Conclusion

This task provided practical knowledge in network security testing and defensive configurations.
By performing scanning, analysis, and firewall management, I gained an in-depth understanding of how to identify, analyze, and mitigate network vulnerabilities.

🏁 Credits

Submitted by:
🧑‍💻 Ravishetti Shivudu
📘 Intern ID: APSPL2519202
🔐 Apex Planet Pvt. Ltd.
📅 Task 2 — Network Security & Scanning
