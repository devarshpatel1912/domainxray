import os


def _env_bool(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return str(val).strip().lower() in ('1', 'true', 'yes', 'on')


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'domainxray-secret-key-2024')
    DEBUG = _env_bool('FLASK_DEBUG', default=True)
    
    # Subdomain scanner settings
    SUBDOMAIN_WORDLIST = os.path.join(os.path.dirname(__file__), 'wordlists', 'subdomains.txt')
    SUBDOMAIN_THREADS = 100
    SUBDOMAIN_TIMEOUT = 2  # seconds
    
    # Port scanning
    COMMON_PORTS = [21, 22, 25, 53, 80, 443, 3306, 3389, 5432, 8080, 8443]
    PORT_TIMEOUT = 2  # seconds
    
    # HTTP request timeout
    HTTP_TIMEOUT = 10  # seconds
