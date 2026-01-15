Language: Python
Category: Network Security/Network Monitoring

NetWatch is a Python based network scanning tool that helps discover active devices, identify open ports, detect operating systems, and retrieve vendor information within a given IP range.
It uses Nmap for scanning and a MAC_vendor_lookup API for manufacturer identification.
This tool supports multiple scan types ranging from quick ping scans to advanced OS and service detection.

Features:
Discovers active devices on a network
Detects open ports(both TCP and UDP)
Detects OS and Services
Identifies device maufacturers using MAC address
Exports Scan result to CSV file

Utilizes multiple Scans:
Ping Scan:- Discovers active devices(Fast)
TCP SYN Scan:- Stealthy Port Scan
UDP Scan:- Service Detection(Slow)
Intense Scan:- OS Detection, scripts and Services

Requirements:
Python 3.x
Nmap (System installation required)
Python Libraries:
          ->python-nmap
 	  ->requests

Permissions:
For advanced scans(TCP, UDP, Intense):
Linux/MacOS: Run with sudo
Windows: Run as Admin

Technologies Used:
Python
Nmap
MAC_VENDOR_LOOKUP API
CSV File Handling

Disclaimer:
This script is intended for educational purpose and authorized network testing purposes only. Unauthorized scanning of networks is illegal and unethical.

This project is open-source and free to use for educational purposes.

Author- Abhishek Raj
