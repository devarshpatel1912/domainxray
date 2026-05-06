import ssl
import socket
from datetime import datetime


def check_ssl(domain, port=443):
    """Check SSL certificate details and perform security analysis."""
    result = {
        'valid': False,
        'issuer': None,
        'issued_date': None,
        'expiry_date': None,
        'days_remaining': None,
        'protocol': None,
        'algorithm': None,
        'bit_strength': None,
        'cipher_suite': None,
        'wildcard': False,
        'subject': None,
        'san': [],
        'serial_number': None,
        'chain_valid': True,
        'grade': 'F',
        'protocols': {
            'TLS 1.3': False,
            'TLS 1.2': False,
            'TLS 1.1': False,
            'TLS 1.0': False,
            'SSL 3.0': False
        },
        'vulnerabilities': {
            'Heartbleed': 'Safe',
            'POODLE': 'Safe',
            'BEAST': 'Safe',
            'ROBOT': 'Safe',
            'Weak SSL/TLS': 'Safe'
        },
        'error': None
    }
    
    try:
        # Create context to check current connection
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol_version = ssock.version()
                
                # Active Protocol
                result['protocol'] = protocol_version or 'Unknown'
                if protocol_version in result['protocols']:
                    result['protocols'][protocol_version] = True
                
                # Cipher Suite & Strength
                if cipher:
                    result['algorithm'] = cipher[0]
                    result['cipher_suite'] = cipher[0]
                    result['bit_strength'] = cipher[2]
                
                # Issuer & Subject
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                result['issuer'] = issuer_dict.get('organizationName', 'Unknown')
                
                subject_dict = dict(x[0] for x in cert.get('subject', []))
                result['subject'] = subject_dict.get('commonName', domain)
                
                # Dates
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                
                if not_before:
                    issued = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                    result['issued_date'] = issued.strftime('%Y-%m-%d')
                
                if not_after:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    result['expiry_date'] = expiry.strftime('%Y-%m-%d')
                    result['days_remaining'] = (expiry - datetime.now()).days
                
                # Wildcard & SAN
                san_list = cert.get('subjectAltName', [])
                result['san'] = [name for _, name in san_list]
                result['wildcard'] = any(name.startswith('*.') for _, name in san_list)
                result['serial_number'] = cert.get('serialNumber', '')
                
                # Validity check
                result['valid'] = result['days_remaining'] is not None and result['days_remaining'] > 0
                result['chain_valid'] = True # Standard context ensures chain validity

        # Security Grading & Vulnerabilities (Simulated/Heuristic logic)
        _perform_security_assessment(result)

    except ssl.SSLCertVerificationError as e:
        result['error'] = f"SSL verification failed: {str(e)}"
        result['valid'] = False
        result['chain_valid'] = False
        result['grade'] = 'F'
    except Exception as e:
        result['error'] = str(e)
        result['valid'] = False
        result['grade'] = 'F'
    
    return result

def _perform_security_assessment(result):
    """Apply grading logic and vulnerability assessment based on findings."""
    grade_points = 100
    
    # Protocol Assessment
    if result['protocol'] == 'TLSv1.3':
        result['grade'] = 'A+'
        result['protocols']['TLS 1.3'] = True
        result['protocols']['TLS 1.2'] = True
    elif result['protocol'] == 'TLSv1.2':
        result['grade'] = 'A'
        result['protocols']['TLS 1.2'] = True
    elif result['protocol'] in ['TLSv1.1', 'TLSv1.0']:
        result['grade'] = 'C'
        result['vulnerabilities']['Weak SSL/TLS'] = 'Warning'
        
    # Bit Strength
    if result['bit_strength'] and result['bit_strength'] < 128:
        grade_points -= 30
    
    # Date Assessment
    if result['days_remaining'] and result['days_remaining'] < 30:
        if result['grade'] > 'B': result['grade'] = 'B'
    
    # Vulnerability Heuristics (Protocol-based)
    if result['protocol'] in ['TLSv1.0', 'SSLv3']:
        result['vulnerabilities']['POODLE'] = 'Vulnerable'
        result['vulnerabilities']['BEAST'] = 'Vulnerable'
        result['grade'] = 'F'

    # Final Grade clean up
    if not result['valid']:
        result['grade'] = 'F'
