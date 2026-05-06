import re
import requests
import dns.resolver

# Standard User-Agent for all requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

# Standard Timeouts
DEFAULT_TIMEOUT = 5
DNS_TIMEOUT = 2
DNS_LIFETIME = 2

def clean_domain_name(domain):
    """Clean and validate domain input."""
    if not domain:
        return ""
    domain = domain.strip().lower()
    # Remove protocol
    domain = re.sub(r'^https?://', '', domain)
    # Remove trailing slash and path
    domain = domain.split('/')[0]
    # Remove port
    domain = domain.split(':')[0]
    return domain

def get_dns_resolver(timeout=None):
    """Returns a pre-configured DNS resolver with tight timeouts."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout or DNS_TIMEOUT
    resolver.lifetime = timeout or DNS_LIFETIME
    return resolver

def safe_requests_get(url, timeout=DEFAULT_TIMEOUT, **kwargs):
    """Perform a requests.get with standardized headers and timeout."""
    headers = kwargs.pop('headers', {})
    if 'User-Agent' not in headers:
        headers['User-Agent'] = USER_AGENT
    if 'Accept-Language' not in headers:
        headers['Accept-Language'] = 'en-US,en;q=0.9'
    
    return requests.get(url, timeout=timeout, headers=headers, **kwargs)

def safe_requests_head(url, timeout=DEFAULT_TIMEOUT, **kwargs):
    """Perform a requests.head with standardized headers and timeout."""
    headers = kwargs.pop('headers', {})
    if 'User-Agent' not in headers:
        headers['User-Agent'] = USER_AGENT
    if 'Accept-Language' not in headers:
        headers['Accept-Language'] = 'en-US,en;q=0.9'
    
    return requests.head(url, timeout=timeout, headers=headers, **kwargs)
