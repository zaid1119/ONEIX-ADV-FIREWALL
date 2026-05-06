# ONEIX-ADV-FIREWALL
A custom Intrusion Prevention System (IPS) and Host-Based Firewall developed in Python to demonstrate deep packet inspection and kernel-level traffic management. This project utilizes the Linux Netfilter Architecture to intercept real-time network traffic and apply security policies at the Network (Layer 3) and Transport (Layer 4) layers.

:Key Technical Achievements
 -Kernel-to-User Space Bridging: Implemented NetfilterQueue to "hook" into the Linux INPUT chain, allowing a Python script to decide the fate of incoming packets.
 -Layer 3 Filtering (IP-Based): Developed a dynamic blacklist to automatically drop traffic from malicious or unauthorized IP addresses.
 -Layer 4 Filtering (Port-Based): Created service-level security to identify and block unauthorized connection attempts to sensitive ports like SSH (22), Telnet (23), and     SMB (445).
 -Deep Packet Inspection (DPI): Leveraged the Scapy library to parse raw packet data, enabling the firewall to differentiate between protocols like TCP, UDP, and ICMP.
 -Security Forensics & Logging: Integrated a professional logging engine that records every blocked attack with a precise timestamp for later analysis.


:Core Technologies
 -Language: Python 3
 -Framework: Linux Netfilter (iptables)
 -Libraries: Scapy, NetfilterQueue
 -Environment: Kali Linux

~Why I Built This
 -As a final-year Bachelor of Computer Applications (BCA) student with a passion for cybersecurity, I built this tool to bridge the gap between academic networking theory     and practical offensive/defensive security implementation. It demonstrates a solid understanding of the OSI model and how modern firewalls protect systems from              unauthorized access.

 How to Use This Project
 -Configure iptables: Redirect traffic to the queue:
 -sudo iptables -I INPUT -j NFQUEUE --queue-num 1

:Run the Firewall:
sudo python3 advanced_firewall.py

View Logs: Check firewall_activity.log for captured events.

Reset: Always flush your rules when finished:
sudo iptables -F
