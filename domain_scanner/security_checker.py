import socket
import concurrent.futures
from .utils import clean_domain_name, get_dns_resolver, safe_requests_get


def check_security(domain, ssl_info=None):
    """Run optimized security checks on a domain."""
    domain = clean_domain_name(domain)
    checks = []
    
    # 1. & 2. Perform a single fetch for all header-based checks
    headers = {}
    session_info = {'https_available': False, 'error': None}
    
    try:
        resp = safe_requests_get(f'https://{domain}', timeout=10, allow_redirects=True)
        headers = resp.headers
        session_info['https_available'] = True
    except Exception as e:
        session_info['error'] = str(e)

    # HTTPS Check
    checks.append({
        'name': 'HTTPS Enabled',
        'description': 'TLS in use' if session_info['https_available'] else 'HTTPS not available',
        'status': 'pass' if session_info['https_available'] else 'fail',
        'icon': 'lock',
        'weight': 15
    })
    
    # SSL Validity
    checks.append(_check_ssl_validity(ssl_info))
    
    # Header checks (Passive, using captured headers)
    checks.append(_check_hsts_passive(headers, session_info['https_available']))
    checks.append(_check_csp_passive(headers))
    checks.append(_check_xframe_passive(headers))
    
    # Active checks
    checks.append(_check_open_ports(domain))
    checks.append(_check_dmarc(domain))
    checks.append(_check_spf(domain))
    
    # Calculate score
    passed = sum(1 for c in checks if c['status'] == 'pass')
    failed = sum(1 for c in checks if c['status'] == 'fail')
    warnings = sum(1 for c in checks if c['status'] == 'warning')
    
    score = 100
    for check in checks:
        if check['status'] == 'fail':
            score -= check.get('weight', 10)
        elif check['status'] == 'warning':
            score -= check.get('weight', 5)
    
    score = max(0, min(100, score))
    
    return {
        'score': score,
        'risk_level': 'Low Risk' if score >= 80 else ('Medium Risk' if score >= 50 else 'High Risk'),
        'checks': checks,
        'passed': passed,
        'failed': failed,
        'warnings': warnings,
        'total': len(checks)
    }

def _check_ssl_validity(ssl_info):
    valid = ssl_info and ssl_info.get('valid')
    return {
        'name': 'Valid SSL Certificate',
        'description': f"Expires {ssl_info.get('expiry_date', 'N/A')}" if valid else 'Invalid or expired certificate',
        'status': 'pass' if valid else 'fail',
        'icon': 'shield-check',
        'weight': 15
    }

def _check_hsts_passive(headers, https_active):
    hsts = headers.get('Strict-Transport-Security')
    if not https_active:
        return {'name': 'HSTS Header', 'description': 'N/A (HTTPS disabled)', 'status': 'warning', 'icon': 'shield', 'weight': 10}
    return {
        'name': 'HSTS Header',
        'description': 'Strict-Transport-Security active' if hsts else 'Missing HSTS header',
        'status': 'pass' if hsts else 'fail',
        'icon': 'shield',
        'weight': 10
    }

def _check_csp_passive(headers):
    csp = headers.get('Content-Security-Policy')
    return {
        'name': 'Content Security Policy',
        'description': 'CSP header configured' if csp else 'CSP header not configured',
        'status': 'pass' if csp else 'fail',
        'icon': 'file-code',
        'weight': 10
    }

def _check_xframe_passive(headers):
    xfo = headers.get('X-Frame-Options')
    return {
        'name': 'X-Frame-Options',
        'description': f'X-Frame-Options: {xfo}' if xfo else 'X-Frame-Options not set',
        'status': 'pass' if xfo else 'fail',
        'icon': 'frame',
        'weight': 10
    }

def _check_open_ports(domain):
    risky_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 3306: 'MySQL', 3389: 'RDP'}
    open_found = []
    
    def scan(p):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                return p if s.connect_ex((domain, p)) == 0 else None
        except: return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(risky_ports)) as ex:
        results = ex.map(scan, risky_ports.keys())
        open_found = [p for p in results if p]

    if not open_found:
        return {'name': 'Port Exposure', 'description': 'No risky ports exposed', 'status': 'pass', 'icon': 'server', 'weight': 10}
    return {'name': 'Port Exposure', 'description': f"Exposed: {', '.join(map(str, open_found))}", 'status': 'fail', 'icon': 'server', 'weight': 10}

def _check_dmarc(domain):
    raw = 'No record found'
    try:
        resolver = get_dns_resolver()
        answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        raw = ' '.join([s.decode() if isinstance(s, bytes) else s for r in answers for s in r.strings])
        status = 'pass' if 'p=reject' in raw.lower() or 'p=quarantine' in raw.lower() else 'warning'
        return {'name': 'DMARC Policy', 'description': 'DMARC configured', 'status': status, 'icon': 'mail', 'weight': 8, 'raw': raw}
    except:
        return {'name': 'DMARC Policy', 'description': 'No DMARC record', 'status': 'fail', 'icon': 'mail', 'weight': 8, 'raw': raw}

def _check_spf(domain):
    raw = 'No record found'
    try:
        resolver = get_dns_resolver()
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = ' '.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
            if 'v=spf1' in txt.lower():
                return {'name': 'SPF Record', 'description': 'SPF record valid', 'status': 'pass', 'icon': 'check-circle', 'weight': 7, 'raw': txt}
    except: pass
    return {'name': 'SPF Record', 'description': 'No SPF record found', 'status': 'fail', 'icon': 'check-circle', 'weight': 7, 'raw': raw}
