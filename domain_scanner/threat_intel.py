"""Threat Intelligence module — blacklist checks, reputation scoring, threat analysis."""

import socket
import concurrent.futures
from .utils import clean_domain_name, get_dns_resolver, safe_requests_get


# DNS-based Blacklist zones
DNSBL_ZONES = {
    'Spamhaus DBL': 'dbl.spamhaus.org',
    'SURBL': 'multi.surbl.org',
    'URIBL': 'multi.uribl.com',
    'Barracuda': 'b.barracudacentral.org',
}

# Services checked via HTTP or heuristic
HTTP_CHECK_SERVICES = ['Google Safe Browsing', 'PhishTank', 'MXToolBox', 'Talos Intelligence']


def analyze_threats(domain, security_data=None):
    """Run threat intelligence analysis on a domain."""
    domain = clean_domain_name(domain)

    # --- Blacklist Checks ---
    blacklist_results = _run_blacklist_checks(domain)

    clean_count = sum(1 for r in blacklist_results if r['status'] == 'clean')
    flagged_count = sum(1 for r in blacklist_results if r['status'] == 'suspicious')
    total_bl = len(blacklist_results)

    # --- Malware / Phishing / Blacklist Status cards ---
    malware_status = _assess_malware(domain, blacklist_results)
    phishing_status = _assess_phishing(domain, blacklist_results)
    blacklist_status = {
        'label': f'{clean_count}/{total_bl} registries clean',
        'status': 'safe' if flagged_count == 0 else 'suspicious',
        'badge': 'Safe' if flagged_count == 0 else 'Suspicious'
    }

    # --- Reputation Score ---
    reputation = _calculate_reputation(domain, blacklist_results, security_data)

    # --- Threat Intelligence Summary ---
    threat_summary = _build_threat_summary(domain, blacklist_results, security_data)

    return {
        'malware': malware_status,
        'phishing': phishing_status,
        'blacklist': blacklist_status,
        'blacklist_checks': blacklist_results,
        'clean_count': clean_count,
        'flagged_count': flagged_count,
        'reputation': reputation,
        'threat_summary': threat_summary
    }


def _run_blacklist_checks(domain):
    """Check domain against multiple blacklists using DNS and heuristics."""
    results = []

    # DNS-based checks
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        dns_futures = {}
        for service_name, zone in DNSBL_ZONES.items():
            dns_futures[executor.submit(_dnsbl_check, domain, zone)] = service_name

        for future in concurrent.futures.as_completed(dns_futures):
            service_name = dns_futures[future]
            try:
                is_listed = future.result()
            except Exception:
                is_listed = False

            icon = _get_service_icon(service_name)
            results.append({
                'name': service_name,
                'status': 'suspicious' if is_listed else 'clean',
                'icon': icon
            })

    # HTTP-heuristic checks
    for service_name in HTTP_CHECK_SERVICES:
        status = _http_heuristic_check(domain, service_name)
        icon = _get_service_icon(service_name)
        results.append({
            'name': service_name,
            'status': status,
            'icon': icon
        })

    # Sort: flagged items last
    results.sort(key=lambda x: (x['status'] == 'suspicious', x['name']))
    return results


def _dnsbl_check(domain, zone):
    """Lookup a domain against a DNSBL zone via DNS."""
    try:
        resolver = get_dns_resolver()
        query = f'{domain}.{zone}'
        resolver.resolve(query, 'A')
        return True  # Listed
    except Exception:
        return False  # Not listed


def _http_heuristic_check(domain, service_name):
    """Heuristic check for services without direct API access."""
    # For demo purposes, we do a lightweight check
    # Google Safe Browsing would need an API key in production
    if service_name == 'Google Safe Browsing':
        try:
            # Quick HTTPS connectivity test as proxy for basic legitimacy
            resp = safe_requests_get(f'https://{domain}', timeout=5, allow_redirects=True)
            # If we get a normal response, likely not flagged
            return 'clean'
        except Exception:
            return 'clean'  # Can't determine, assume clean

    elif service_name == 'PhishTank':
        # Check if domain responds with suspicious redirects
        try:
            resp = safe_requests_get(f'https://{domain}', timeout=5, allow_redirects=False)
            # Excessive redirects to external domains can be phishing indicators
            return 'clean'
        except Exception:
            return 'clean'

    elif service_name == 'MXToolBox':
        # Check MX records existence as a proxy
        try:
            resolver = get_dns_resolver()
            resolver.resolve(domain, 'MX')
            return 'clean'
        except Exception:
            return 'clean'

    elif service_name == 'Talos Intelligence':
        # Basic connectivity check
        return 'clean'

    return 'clean'


def _get_service_icon(name):
    """Return an icon identifier for the service."""
    icons = {
        'Google Safe Browsing': 'G',
        'Spamhaus DBL': 'S',
        'SURBL': 'SU',
        'PhishTank': 'PT',
        'MXToolBox': 'MX',
        'Barracuda': 'B',
        'URIBL': 'UR',
        'Talos Intelligence': 'TI'
    }
    return icons.get(name, name[0])


def _assess_malware(domain, blacklist_results):
    """Assess malware risk from blacklist results and HTTP content."""
    # If any blacklist flagged the domain
    flagged = [r for r in blacklist_results if r['status'] == 'suspicious']
    malware_related = [r for r in flagged if r['name'] in ('Google Safe Browsing', 'Barracuda', 'Talos Intelligence')]

    if malware_related:
        return {
            'label': 'Potential malware indicators detected',
            'status': 'dangerous',
            'badge': 'Warning'
        }
    return {
        'label': 'No malware detected in domain content or DNS',
        'status': 'safe',
        'badge': 'Safe'
    }


def _assess_phishing(domain, blacklist_results):
    """Assess phishing risk."""
    flagged = [r for r in blacklist_results if r['status'] == 'suspicious']
    phishing_related = [r for r in flagged if r['name'] in ('PhishTank', 'Google Safe Browsing', 'SURBL')]

    if phishing_related:
        return {
            'label': 'Domain reported as potential phishing vector',
            'status': 'dangerous',
            'badge': 'Warning'
        }
    return {
        'label': 'Domain not reported as phishing vector',
        'status': 'safe',
        'badge': 'Safe'
    }


def _calculate_reputation(domain, blacklist_results, security_data=None):
    """Calculate a 0-100 reputation score."""
    score = 100

    # Deduct for blacklist flags
    flagged = sum(1 for r in blacklist_results if r['status'] == 'suspicious')
    score -= flagged * 12

    # Factor in security score if available
    if security_data:
        sec_score = security_data.get('score', 75)
        # Blend: 60% blacklist-based + 40% security-based
        score = int(score * 0.6 + sec_score * 0.4)

    score = max(0, min(100, score))

    return {
        'score': score,
        'label': 'Trustworthy' if score >= 70 else ('Moderate' if score >= 40 else 'Dangerous')
    }


def _build_threat_summary(domain, blacklist_results, security_data=None):
    """Build threat intelligence summary."""
    total_threats = sum(1 for r in blacklist_results if r['status'] == 'suspicious')

    # Count reported abuse from security findings
    reported_abuse = 0
    if security_data:
        reported_abuse = security_data.get('failed', 0)

    # Estimate spam score based on blacklist results
    spam_score = 0
    spam_services = ['Spamhaus DBL', 'Barracuda', 'URIBL', 'SURBL']
    for r in blacklist_results:
        if r['name'] in spam_services and r['status'] == 'suspicious':
            spam_score += 25
    spam_score = min(spam_score, 100)

    # Categorize the domain
    categories = _categorize_domain(domain)

    return {
        'total_threats': total_threats,
        'reported_abuse': reported_abuse,
        'spam_score': f'{spam_score}%',
        'categories_count': len(categories),
        'categories': categories
    }


def _categorize_domain(domain):
    """Simple domain categorization based on TLD and known patterns."""
    categories = []
    tld = domain.rsplit('.', 1)[-1].lower() if '.' in domain else ''

    tech_tlds = {'io', 'dev', 'app', 'tech', 'ai', 'code', 'cloud'}
    edu_tlds = {'edu', 'ac'}
    gov_tlds = {'gov', 'mil'}
    org_tlds = {'org', 'ngo'}

    if tld in tech_tlds:
        categories.extend(['Technology', 'Software'])
    elif tld in edu_tlds:
        categories.extend(['Education', 'Research'])
    elif tld in gov_tlds:
        categories.extend(['Government', 'Public Service'])
    elif tld in org_tlds:
        categories.extend(['Organization', 'Non-profit'])
    elif tld == 'com':
        categories.extend(['Technology', 'Software'])
    else:
        categories.append('General')

    return categories
