import socket
import requests
import concurrent.futures
import re

def check_ports(target):
    """Scan common ports for a given IP or domain."""
    ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy"
    }
    
    results = []
    
    # Resolve domain to IP if needed
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return f"Error: Could not resolve target {target}"

    def check_single_port(port, service):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, service, "open" if result == 0 else "closed"

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_port = [executor.submit(check_single_port, p, s) for p, s in ports.items()]
        for future in concurrent.futures.as_completed(future_to_port):
            port, service, status = future.result()
            results.append({
                "port": port,
                "service": service,
                "status": status
            })
            
    # Sort results by port number
    results.sort(key=lambda x: x['port'])
    
    # Format output
    output = f"Port Scan Results for {target} ({ip})\n"
    output += "-" * 40 + "\n"
    output += f"{'PORT':<8} {'STATUS':<10} {'SERVICE':<12}\n"
    for r in results:
        output += f"{r['port']:<8} {r['status']:<10} {r['service']:<12}\n"
        
    return output

def get_http_headers(url):
    """Fetch HTTP response headers for a URL."""
    if not url.startswith('http'):
        url = 'https://' + url
        
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        output = f"HTTP Response Headers for {url}\n"
        output += "-" * 40 + "\n"
        output += f"Status: {response.status_code} {response.reason}\n\n"
        
        for key, value in response.headers.items():
            output += f"{key}: {value}\n"
            
        return output
    except Exception as e:
        return f"Error fetching headers: {str(e)}"

def check_usernames(username):
    """Check availability across 15+ global platforms."""
    platforms = {
        "GitHub": "https://github.com/{}",
        "Twitter": "https://twitter.com/{}",
        "Instagram": "https://www.instagram.com/{}/",
        "Reddit": "https://www.reddit.com/user/{}",
        "YouTube": "https://www.youtube.com/@{}",
        "TikTok": "https://www.tiktok.com/@{}",
        "Pinterest": "https://www.pinterest.com/{}/",
        "Facebook": "https://www.facebook.com/{}",
        "Telegram": "https://t.me/{}",
        "Discord": "https://discord.com/users/{}",
        "Steam": "https://steamcommunity.com/id/{}",
        "Twitch": "https://www.twitch.tv/{}",
        "Snapchat": "https://www.snapchat.com/add/{}",
        "VK": "https://vk.com/{}",
        "Weibo": "https://weibo.com/n/{}"
    }
    
    results = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    def check_platform(name, url_pattern):
        url = url_pattern.format(username)
        try:
            res = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            if res.status_code == 200:
                # Custom logic for some platforms where 200 doesn't mean "found"
                if name == "Reddit" and "user not found" in res.text.lower():
                    return name, "Available", url
                return name, "Taken", url
            elif res.status_code == 404:
                return name, "Available", url
            else:
                return name, f"Error ({res.status_code})", url
        except Exception:
            return name, "Timeout", url

    output = f"Global Username Check for '{username}'\n"
    output += "-" * 40 + "\n"
    output += f"{'PLATFORM':<15} {'STATUS':<15}\n"
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_platform, name, pattern) for name, pattern in platforms.items()]
        for future in concurrent.futures.as_completed(futures):
            name, status, url = future.result()
            output += f"{name:<15} {status:<15}\n"
            
    return output

def reverse_ip_lookup(ip):
    """DNS-based reverse lookup."""
    try:
        host, alias, addresslist = socket.gethostbyaddr(ip)
        output = f"Reverse DNS Result for {ip}\n"
        output += "-" * 40 + "\n"
        output += f"Hostname: {host}\n"
        if alias:
            output += f"Aliases: {', '.join(alias)}\n"
        return output
    except Exception as e:
        return f"Error: No PTR record found for {ip}."

def lookup_emails(domain):
    """Email discovery patterns."""
    common = ['admin', 'info', 'support', 'contact', 'billing', 'sales', 'tech']
    output = f"Potential Email Patterns for {domain}\n"
    output += "-" * 40 + "\n"
    for p in common:
        output += f"- {p}@{domain}\n"
    return output
