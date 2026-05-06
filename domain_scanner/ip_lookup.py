import socket
from ipwhois import IPWhois
import ipaddress
from .utils import safe_requests_get

def lookup_ip(ip_address):
    """Look up IP information, prioritizing real WHOIS (RDAP) data."""
    result = {
        'ip': ip_address,
        'country': None,
        'country_code': None,
        'city': None,
        'region': None,
        'lat': None,
        'lon': None,
        'isp': None,
        'hosting': None,
        'org': None,
        'asn': None,
        'error': None,
        'whois_description': None
    }
    
    if not ip_address:
        result['error'] = 'No IP address provided'
        return result

    try:
        parsed_ip = ipaddress.ip_address(ip_address)
        if parsed_ip.is_private or parsed_ip.is_loopback:
            result['error'] = 'IP is not publicly routable'
            return result
    except ValueError:
        result['error'] = 'Invalid IP address'
        return result

    # --- Step 1: Real WHOIS (RDAP) lookup (Core Source) ---
    try:
        obj = IPWhois(ip_address)
        rdap = obj.lookup_rdap(depth=1)
        
        result['asn'] = rdap.get('asn')
        result['whois_description'] = rdap.get('asn_description')
        
        # Prioritize WHOIS for hosting/ISP info
        asn_desc = rdap.get('asn_description', '')
        result['hosting'] = asn_desc
        result['isp'] = asn_desc
        
        # Try to get more granular org info from objects
        objects = rdap.get('objects', {})
        for obj_id, obj_data in objects.items():
            if 'contact' in obj_data:
                contact = obj_data['contact']
                if contact.get('name'):
                    result['org'] = contact.get('name')
                    break
                    
    except Exception as e:
        print(f"IPWhois error: {str(e)}")

    # --- Step 2: Geolocation API (for city/coordinates) ---
    try:
        resp = safe_requests_get(f'https://ipwho.is/{ip_address}', timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('success'):
                # Only use API if WHOIS didn't give a better org name
                if not result['hosting']:
                    result['hosting'] = data.get('connection', {}).get('org') or data.get('isp')
                
                result['country'] = data.get('country')
                result['country_code'] = str(data.get('country_code') or '').lower()
                result['city'] = data.get('city')
                result['region'] = data.get('region')
                result['lat'] = data.get('lat')
                result['lon'] = data.get('lon')
                
                # If WHOIS didn't find an org, use the API's one
                if not result['org']:
                    result['org'] = data.get('org')
    except Exception:
        pass

    # Final cleanup
    if result['hosting'] and ' - ' in result['hosting']:
        # Clean up some common ASN string formats like "ASN123 - Company Name"
        parts = result['hosting'].split(' - ', 1)
        if len(parts) > 1:
            result['hosting'] = parts[1]

    return result

def reverse_dns(ip_address):
    """Perform a reverse DNS lookup."""
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except Exception:
        return None
