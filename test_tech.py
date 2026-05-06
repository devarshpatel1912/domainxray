import sys
sys.path.insert(0, '.')
from domain_scanner.tech_detector import detect_technologies

domains = ['github.com', 'microsoft.com', 'shopify.com']
for domain in domains:
    print(f"\n{'='*50}")
    print(f"  {domain}")
    print(f"{'='*50}")
    result = detect_technologies(domain)
    print(f"Detected: {result['counts']['detected']}")
    print(f"Not detected: {result['counts']['not_detected']}")
    cats = {}
    for t in result['detected']:
        cats.setdefault(t['category'], []).append(f"{t['name']}" + (f" ({t['version']})" if t['version'] else ""))
    for k, v in cats.items():
        print(f"  {k}: {', '.join(v)}")
