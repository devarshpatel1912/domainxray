import whois
from datetime import datetime, timezone
import re


def _make_naive(dt):
    """Convert a datetime to timezone-naive (UTC) for safe comparison."""
    if dt is None:
        return None
    if not isinstance(dt, datetime):
        return dt
    if dt.tzinfo is not None:
        # Convert to UTC then strip timezone
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _normalize_date_value(value):
    """Normalize WHOIS date values into datetime list."""
    if value is None:
        return []
    candidates = value if isinstance(value, list) else [value]
    normalized = []
    for item in candidates:
        item = _make_naive(item)
        if isinstance(item, datetime):
            normalized.append(item)
            continue
        parsed = _parse_datetime_string(item)
        if isinstance(parsed, datetime):
            normalized.append(parsed)
    return normalized


def _parse_datetime_string(value):
    """Parse common WHOIS date string formats."""
    if not value or not isinstance(value, str):
        return None
    cleaned = re.sub(r'\s+', ' ', value.strip())
    cleaned = cleaned.replace('Z', '+00:00')

    try:
        return _make_naive(datetime.fromisoformat(cleaned))
    except Exception:
        pass

    for fmt in (
        '%Y-%m-%d',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%dT%H:%M:%S.%f%z',
        '%d-%b-%Y',
        '%d-%b-%Y %H:%M:%S %Z',
        '%d.%m.%Y %H:%M:%S',
    ):
        try:
            return _make_naive(datetime.strptime(cleaned, fmt))
        except Exception:
            continue
    return None


def _pick_date(value, mode):
    """
    Pick the most reliable date from WHOIS responses.
    mode:
      - 'min' for creation date (earliest known registration)
      - 'max' for expiration/updated dates (latest known value)
    """
    dates = _normalize_date_value(value)
    if not dates:
        return None
    return min(dates) if mode == 'min' else max(dates)


def _format_date(dt):
    """Format a datetime to YYYY-MM-DD string."""
    if dt and isinstance(dt, datetime):
        return dt.strftime('%Y-%m-%d')
    return str(dt) if dt else 'N/A'


def lookup_whois(domain):
    """Fetch WHOIS information for a domain."""
    result = {
        'domain': domain,
        'registrar': None,
        'creation_date': None,
        'creation_date_formatted': 'N/A',
        'expiration_date': None,
        'expiration_date_formatted': 'N/A',
        'updated_date': None,
        'updated_date_formatted': 'N/A',
        'domain_age': None,
        'domain_age_years': 0,
        'nameservers': [],
        'status': 'Unknown',
        'registrant': {},
        'is_active': False,
        'raw_status': [],
        'error': None
    }
    
    try:
        w = whois.whois(domain)
    except Exception as e:
        result['error'] = f"WHOIS lookup failed: {str(e)}"
        return result
    
    # --- Registrar ---
    try:
        result['registrar'] = w.registrar or 'Unknown'
    except Exception:
        result['registrar'] = 'Unknown'
    
    # --- Dates (handle timezone-aware vs naive) ---
    try:
        raw_created = getattr(w, 'creation_date', None)
        result['creation_date'] = _pick_date(raw_created, 'min')
        result['creation_date_formatted'] = _format_date(result['creation_date'])
    except Exception:
        pass
    
    try:
        raw_expiry = getattr(w, 'expiration_date', None)
        result['expiration_date'] = _pick_date(raw_expiry, 'max')
        result['expiration_date_formatted'] = _format_date(result['expiration_date'])
    except Exception:
        pass
    
    try:
        raw_updated = getattr(w, 'updated_date', None)
        result['updated_date'] = _pick_date(raw_updated, 'max')
        result['updated_date_formatted'] = _format_date(result['updated_date'])
    except Exception:
        pass
    
    # --- Domain Age ---
    try:
        if result['creation_date'] and isinstance(result['creation_date'], datetime):
            now = datetime.now()  # Both are naive now
            age_delta = now - result['creation_date']
            years = age_delta.days // 365
            result['domain_age'] = f"{years} years"
            result['domain_age_years'] = years
    except Exception:
        pass
    
    # --- Nameservers ---
    try:
        if w.name_servers:
            servers = w.name_servers
            if isinstance(servers, list):
                # Deduplicate and lowercase
                seen = set()
                ns_list = []
                for ns in servers:
                    ns_lower = ns.lower().rstrip('.')
                    if ns_lower not in seen:
                        seen.add(ns_lower)
                        ns_list.append(ns_lower)
                result['nameservers'] = ns_list
            else:
                result['nameservers'] = [servers.lower().rstrip('.')]
    except Exception:
        pass
    
    # --- Status ---
    try:
        if w.status:
            if isinstance(w.status, list):
                result['raw_status'] = w.status
            else:
                result['raw_status'] = [w.status]
    except Exception:
        pass
    
    # --- Check if active ---
    try:
        if result['expiration_date'] and isinstance(result['expiration_date'], datetime):
            now = datetime.now()  # Both are naive
            result['is_active'] = result['expiration_date'] > now
        elif getattr(w, 'domain_name', None):
            result['is_active'] = True
        else:
            result['is_active'] = False
    except Exception:
        # If we can't determine, check if domain_name exists
        try:
            result['is_active'] = bool(getattr(w, 'domain_name', None))
        except Exception:
            pass
    
    result['status'] = 'Active' if result['is_active'] else 'Expired'
    
    # --- Registrant info ---
    try:
        result['registrant'] = {
            'name': getattr(w, 'name', None),
            'organization': getattr(w, 'org', None),
            'country': getattr(w, 'country', None),
            'state': getattr(w, 'state', None),
            'city': getattr(w, 'city', None),
            'email': getattr(w, 'emails', None)
        }
    except Exception:
        pass
    
    # --- Convert datetime objects to strings for JSON serialization ---
    for key in ['creation_date', 'expiration_date', 'updated_date']:
        val = result[key]
        if isinstance(val, datetime):
            result[key] = val.isoformat()
    
    return result
