# Python Reconnaissance & Security Scanning Script

A lightweight Python script utilizing `scapy`, `requests`, `BeautifulSoup`, and `socket` to perform basic reconnaissance, DNS lookups, port scanning, and quick checks for common web vulnerabilities (SQLi, Code Injection, LDAP injection).

## Features
- **DNS Querying:** Resolves domain A records using Scapy.
- **Port Scanning:** Checks common TCP ports and grabs service banners using raw sockets.
- **Web Scraping & Recon:** Analyzes headers, security controls, redirects, and content fingerprints.
- **Basic Vulnerability Checks:** Runs ultra-simple payloads to spot potential SQL injection, code injection, and LDAP bypass vectors.
