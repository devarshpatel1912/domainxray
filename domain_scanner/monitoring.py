"""Monitoring module — response time, uptime tracking, watched domains."""

import time
import random
import hashlib
import concurrent.futures
from .utils import clean_domain_name, safe_requests_get
from .ssl_checker import check_ssl
from .storage import get_watched_domains


def _deterministic_seed(key):
    """Return a deterministic integer seed from a string key.

    Uses MD5 (not for security, just for consistency) so the seed is
    identical across different Python processes, machines, and OS versions.
    Python's built-in hash() is randomised per process (PYTHONHASHSEED).
    """
    return int(hashlib.md5(key.encode('utf-8')).hexdigest(), 16) % (10 ** 9)


# Default watched domains for demonstration
DEFAULT_WATCHED = [
    'example.com',
    'github.com',
    'cloudflare.com',
    'myoldapp.io',
    'testproject.dev'
]


def get_monitoring_data(domain):
    """Get full monitoring dashboard data for a domain."""
    domain = clean_domain_name(domain)

    # Build watched domains list — include the scanned domain at the top
    watched_list = [domain]
    saved_watched = get_watched_domains()
    
    for d in saved_watched:
        if d != domain and len(watched_list) < 6:
            watched_list.append(d)

    # Fetch status for all watched domains in parallel
    watched_domains = _check_watched_domains(watched_list)

    # Calculate stats
    online = sum(1 for d in watched_domains if d['status'] == 'Online')
    offline = sum(1 for d in watched_domains if d['status'] == 'Offline')
    degraded = sum(1 for d in watched_domains if d['status'] == 'Degraded')
    total = len(watched_domains)

    # Get response time history for the primary domain
    response_data = _get_response_history(domain, watched_domains)

    return {
        'stats': {
            'monitored': total,
            'online': online,
            'offline': offline,
            'degraded': degraded
        },
        'watched_domains': watched_domains,
        'response_time': response_data
    }


def _check_watched_domains(domains):
    """Check status of multiple domains in parallel."""
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(_check_single_domain, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                d = futures[future]
                results.append({
                    'domain': d,
                    'status': 'Offline',
                    'uptime': 'N/A',
                    'ssl_days': 'N/A',
                    'response_time': None,
                    'last_check': 'just now'
                })

    # Maintain original order
    domain_order = {d: i for i, d in enumerate(domains)}
    results.sort(key=lambda x: domain_order.get(x['domain'], 999))
    return results


def _check_single_domain(domain):
    """Check a single domain's status, response time, and SSL."""
    result = {
        'domain': domain,
        'status': 'Offline',
        'uptime': 'N/A',
        'ssl_days': 'N/A',
        'response_time': None,
        'last_check': '2 min ago'
    }

    # Measure response time
    try:
        start = time.time()
        resp = safe_requests_get(f'https://{domain}', timeout=10, allow_redirects=True)
        elapsed_ms = int((time.time() - start) * 1000)
        result['response_time'] = elapsed_ms

        status_code = resp.status_code
        if 200 <= status_code < 400:
            result['status'] = 'Online'
            # Simulate uptime (in production this would come from historical data)
            result['uptime'] = _simulate_uptime(domain)
        elif 400 <= status_code < 500:
            result['status'] = 'Degraded'
            result['uptime'] = _simulate_uptime(domain, degraded=True)
        else:
            result['status'] = 'Degraded'
            result['uptime'] = _simulate_uptime(domain, degraded=True)
    except Exception:
        # Try HTTP if HTTPS fails
        try:
            start = time.time()
            resp = safe_requests_get(f'http://{domain}', timeout=10, allow_redirects=True)
            elapsed_ms = int((time.time() - start) * 1000)
            result['response_time'] = elapsed_ms
            result['status'] = 'Degraded'
            result['uptime'] = _simulate_uptime(domain, degraded=True)
        except Exception:
            result['status'] = 'Offline'
            result['uptime'] = _simulate_uptime(domain, offline=True)

    # Check SSL
    try:
        ssl_info = check_ssl(domain)
        if ssl_info and ssl_info.get('days_remaining') is not None:
            result['ssl_days'] = f"{ssl_info['days_remaining']}d"
        elif ssl_info and ssl_info.get('error'):
            result['ssl_days'] = 'N/A'
    except Exception:
        result['ssl_days'] = 'N/A'

    return result


def _simulate_uptime(domain, degraded=False, offline=False):
    """Generate realistic uptime percentage based on domain status."""
    if offline:
        # Use consistent seed for consistent results per domain
        random.seed(_deterministic_seed(domain))
        return f"{random.uniform(75, 88):.1f}%"
    elif degraded:
        random.seed(_deterministic_seed(domain))
        return f"{random.uniform(90, 96):.1f}%"
    else:
        random.seed(_deterministic_seed(domain))
        return f"{random.uniform(99, 100):.2f}%"


def _get_response_history(domain, watched_domains):
    """Get response time data for the primary domain."""
    # Find the actual response time for this domain
    actual_rt = None
    for wd in watched_domains:
        if wd['domain'] == domain:
            actual_rt = wd['response_time']
            break

    if actual_rt is None:
        actual_rt = 150

    # Generate a deterministic base response time for this domain (100-500ms)
    random.seed(_deterministic_seed(domain + 'base_rt'))
    base_rt = random.randint(100, 500)

    # Generate simulated 7-day history (for chart rendering)
    random.seed(_deterministic_seed(domain + 'history'))
    days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    history = []
    for day in days:
        # Vary around the base response time
        variance = random.uniform(0.7, 1.4)
        rt = int(base_rt * variance)
        history.append({'day': day, 'value': rt})

    # Calculate stats
    values = [h['value'] for h in history]
    avg_response = int(sum(values) / len(values)) if values else actual_rt

    # Simulate uptime and incidents
    uptime_7d = _simulate_uptime(domain)
    random.seed(_deterministic_seed(domain + 'incidents'))
    incidents = random.randint(0, 3)

    # Last 24h uptime bar data (48 half-hour slots)
    random.seed(_deterministic_seed(domain + 'slots'))
    last_24h = []
    for i in range(48):
        # 95% chance of being up
        if random.random() < 0.95:
            last_24h.append(1)
        else:
            last_24h.append(0)

    return {
        'domain': domain,
        'history': history,
        'avg_response': avg_response,
        'uptime_7d': uptime_7d,
        'incidents_7d': incidents,
        'last_24h': last_24h
    }
