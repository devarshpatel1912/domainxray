import concurrent.futures
import time
import os
import socket
from .utils import clean_domain_name, get_dns_resolver, safe_requests_head, safe_requests_get


def load_wordlist(path):
    """Load subdomain wordlist from file (order preserved, duplicates skipped)."""
    subdomains = []
    seen = set()
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith('#') and line not in seen:
                    seen.add(line)
                    subdomains.append(line)
    return subdomains


def _resolve_ip(resolver, full_domain):
    """Resolve A record, then AAAA, with socket fallback."""
    try:
        answers = resolver.resolve(full_domain, 'A')
        return answers[0].address
    except Exception:
        pass
    
    try:
        # Fallback to system resolver for maximum compatibility
        return socket.gethostbyname(full_domain)
    except Exception:
        pass

    try:
        answers = resolver.resolve(full_domain, 'AAAA')
        return answers[0].address
    except Exception:
        return None


def _http_probe(full_domain, timeout):
    """
    Try HEAD then GET on HTTPS then HTTP. Many sites reject HEAD (405) or only
    answer reliably to GET; any HTTP status means the host is serving HTTP(S).
    Returns (status_code, elapsed_ms) or (None, None).
    """
    for scheme in ('https', 'http'):
        url = f'{scheme}://{full_domain}'
        for use_get in (False, True):
            try:
                start = time.time()
                if use_get:
                    resp = safe_requests_get(
                        url, timeout=timeout, allow_redirects=True, stream=True
                    )
                    try:
                        elapsed = int((time.time() - start) * 1000)
                        code = resp.status_code
                        return code, elapsed
                    finally:
                        resp.close()
                else:
                    resp = safe_requests_head(
                        url, timeout=timeout, allow_redirects=True
                    )
                    elapsed = int((time.time() - start) * 1000)
                    return resp.status_code, elapsed
            except Exception:
                continue
    return None, None


def _tcp_open(host, port, timeout=2):
    """True if host accepts TCP on port (IPv4 or IPv6 literal)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_subdomain(subdomain, domain, timeout=5):
    """Check if a subdomain exists and whether it responds on the web."""
    full_domain = f"{subdomain}.{domain}"
    result = {
        'subdomain': full_domain,
        'status': 'Inactive',
        'http_code': None,
        'response_time': None,
        'ip': None,
        'reachability': None,
    }

    resolver = get_dns_resolver(timeout=timeout)
    ip = _resolve_ip(resolver, full_domain)
    if not ip:
        return result

    result['ip'] = ip
    code, elapsed = _http_probe(full_domain, timeout)

    if code is not None:
        result['status'] = 'Active'
        result['http_code'] = code
        result['response_time'] = elapsed
        result['reachability'] = 'http'
        return result

    # No HTTP answer (blocked, timeout, or non-HTTP service) — try open ports
    t = min(float(timeout), 3.0)
    if _tcp_open(ip, 443, t) or _tcp_open(ip, 80, t):
        result['status'] = 'Active'
        result['reachability'] = 'tcp'
        return result

    result['status'] = 'DNS-Only'
    result['reachability'] = 'dns'
    return result


def scan_subdomains(domain, wordlist_path, max_threads=20, timeout=5):
    """Scan for subdomains using a wordlist with parallel threads."""
    domain = clean_domain_name(domain)
    subdomains = load_wordlist(wordlist_path)
    results = []
    
    if not subdomains:
        return {'subdomains': [], 'total': 0, 'active': 0, 'dns_only': 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(check_subdomain, sub, domain, timeout): sub 
            for sub in subdomains
        }
        
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result.get('ip'):  # Only include resolved subdomains
                    results.append(result)
            except Exception:
                continue
    
    reach_rank = {'http': 0, 'tcp': 1, 'dns': 2}
    results.sort(
        key=lambda x: (
            reach_rank.get(x.get('reachability'), 9),
            x.get('subdomain', ''),
        )
    )

    active_count = sum(1 for r in results if r.get('status') == 'Active')
    dns_only_count = sum(1 for r in results if r.get('reachability') == 'dns')

    return {
        'subdomains': results,
        'total': len(results),
        'active': active_count,
        'dns_only': dns_only_count,
    }
