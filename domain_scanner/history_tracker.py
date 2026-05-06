from datetime import datetime


def _parse_date(val):
    """Parse a date value that could be a datetime, ISO string, or formatted string."""
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d', '%Y-%m-%dT%H:%M:%S.%f']:
            try:
                return datetime.strptime(val.split('+')[0].split('Z')[0], fmt)
            except ValueError:
                continue
    return None


def build_history(whois_data, ssl_data):
    """Build a domain history timeline from WHOIS and SSL data."""
    events = []
    
    # Domain Registration
    creation_date = _parse_date(whois_data.get('creation_date'))
    if creation_date:
        events.append({
            'date': creation_date.strftime('%Y-%m-%d'),
            'timestamp': creation_date.timestamp(),
            'title': 'Domain Registration',
            'description': f'Domain registered with {whois_data.get("registrar", "unknown registrar")}',
            'type': 'registration',
            'icon': 'flag'
        })
    
    # Domain Updated (could mean renewal or DNS change)
    updated_date = _parse_date(whois_data.get('updated_date'))
    if updated_date:
        if creation_date and updated_date > creation_date:
            events.append({
                'date': updated_date.strftime('%Y-%m-%d'),
                'timestamp': updated_date.timestamp(),
                'title': 'Domain Updated',
                'description': 'WHOIS record updated. May indicate renewal or DNS change.',
                'type': 'dns',
                'icon': 'refresh'
            })
    
    # Domain Expiration (future event)
    expiration_date = _parse_date(whois_data.get('expiration_date'))
    if expiration_date:
        is_expired = expiration_date < datetime.now()
        events.append({
            'date': expiration_date.strftime('%Y-%m-%d'),
            'timestamp': expiration_date.timestamp(),
            'title': 'Domain Expiry' if is_expired else 'Domain Renewal Due',
            'description': f'Domain {"expired" if is_expired else "set to expire"} on {expiration_date.strftime("%B %d, %Y")}',
            'type': 'expiry' if is_expired else 'renewal',
            'icon': 'calendar'
        })
    
    # SSL Certificate Events
    if ssl_data and not ssl_data.get('error'):
        # SSL Issued
        if ssl_data.get('issued_date'):
            try:
                issued_dt = datetime.strptime(ssl_data['issued_date'], '%Y-%m-%d')
                events.append({
                    'date': ssl_data['issued_date'],
                    'timestamp': issued_dt.timestamp(),
                    'title': 'SSL Certificate Issued',
                    'description': f'Certificate issued by {ssl_data.get("issuer", "unknown")}. Protocol: {ssl_data.get("protocol", "unknown")}',
                    'type': 'ssl',
                    'icon': 'shield'
                })
            except (ValueError, TypeError):
                pass
        
        # SSL Expiry
        if ssl_data.get('expiry_date'):
            try:
                expiry_dt = datetime.strptime(ssl_data['expiry_date'], '%Y-%m-%d')
                events.append({
                    'date': ssl_data['expiry_date'],
                    'timestamp': expiry_dt.timestamp(),
                    'title': 'SSL Certificate Expiry',
                    'description': f'Certificate expires. Days remaining: {ssl_data.get("days_remaining", "unknown")}',
                    'type': 'ssl',
                    'icon': 'shield-alert'
                })
            except (ValueError, TypeError):
                pass
    
    # Sort events by date (newest first)
    events.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    
    return {
        'events': events,
        'total': len(events)
    }
