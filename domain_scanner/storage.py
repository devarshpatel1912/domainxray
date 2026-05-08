import json
import os

WATCHED_FILE = 'watched_domains.json'

def get_watched_domains():
    if not os.path.exists(WATCHED_FILE):
        return ['example.com', 'github.com', 'cloudflare.com', 'myoldapp.io', 'testproject.dev']
    try:
        with open(WATCHED_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def add_watched_domain(domain):
    domains = get_watched_domains()
    if domain not in domains:
        domains.append(domain)
        with open(WATCHED_FILE, 'w') as f:
            json.dump(domains, f)
        return True
    return False

def remove_watched_domain(domain):
    domains = get_watched_domains()
    if domain in domains:
        domains.remove(domain)
        with open(WATCHED_FILE, 'w') as f:
            json.dump(domains, f)
        return True
    return False
