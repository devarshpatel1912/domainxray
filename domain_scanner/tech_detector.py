import re
import warnings
import asyncio
#from Wappalyzer import Wappalyzer, WebPage
from .utils import safe_requests_get
from .deep_detector import run_deep_scan

# Suppress the Wappalyzer regex warnings
warnings.filterwarnings("ignore", message="Caught '.*' compiling regex")

# Initialize Wappalyzer once (it's heavy to load)
try:
    # Use latest signatures if possible
    _wappalyzer = Wappalyzer.latest()
except Exception:
    # Fallback to internal signatures if network is down or error
    #_wappalyzer = Wappalyzer.new()

# ============================================
# Comprehensive Technology Watchlist
# ============================================

TECH_WATCHLIST = [
    # === JavaScript Frameworks ===
    {'name': 'React', 'category': 'JavaScript frameworks', 'color': '#61dafb', 'icon': 'atom'},
    {'name': 'Next.js', 'category': 'JavaScript frameworks', 'color': '#000000', 'icon': 'file-code'},
    {'name': 'Vue.js', 'category': 'JavaScript frameworks', 'color': '#42b883', 'icon': 'atom'},
    {'name': 'Nuxt.js', 'category': 'JavaScript frameworks', 'color': '#00dc82', 'icon': 'file-code'},
    {'name': 'Angular', 'category': 'JavaScript frameworks', 'color': '#dd0031', 'icon': 'atom'},
    {'name': 'Svelte', 'category': 'JavaScript frameworks', 'color': '#ff3e00', 'icon': 'atom'},
    {'name': 'Gatsby', 'category': 'JavaScript frameworks', 'color': '#663399', 'icon': 'atom'},
    {'name': 'Astro', 'category': 'JavaScript frameworks', 'color': '#ff5d01', 'icon': 'atom'},

    # === CMS & Ecommerce ===
    {'name': 'WordPress', 'category': 'CMS', 'color': '#21759b', 'icon': 'layout'},
    {'name': 'Adobe Experience Manager', 'category': 'CMS', 'color': '#ff0000', 'icon': 'layout'},
    {'name': 'Shopify', 'category': 'Ecommerce', 'color': '#96bf48', 'icon': 'cart'},
    {'name': 'WooCommerce', 'category': 'Ecommerce', 'color': '#7f54b3', 'icon': 'cart'},
    {'name': 'Magento', 'category': 'Ecommerce', 'color': '#ee672f', 'icon': 'cart'},
    {'name': 'Wix', 'category': 'CMS', 'color': '#0c6efc', 'icon': 'layout'},
    {'name': 'Webflow', 'category': 'CMS', 'color': '#4353ff', 'icon': 'layout'},

    # === Analytics ===
    {'name': 'Google Analytics', 'category': 'Analytics', 'color': '#e37400', 'icon': 'bar-chart'},
    {'name': 'Microsoft Clarity', 'category': 'Analytics', 'color': '#0078d4', 'icon': 'bar-chart'},
    {'name': 'Hotjar', 'category': 'Analytics', 'color': '#fd3a5c', 'icon': 'bar-chart'},
    {'name': 'Facebook Pixel', 'category': 'Analytics', 'color': '#1877f2', 'icon': 'bar-chart'},
    {'name': 'LinkedIn Insight Tag', 'category': 'Analytics', 'color': '#0a66c2', 'icon': 'bar-chart'},
    {'name': 'comScore', 'category': 'Analytics', 'color': '#000000', 'icon': 'bar-chart'},
    {'name': 'Contentsquare', 'category': 'Analytics', 'color': '#2400ff', 'icon': 'bar-chart'},
    {'name': 'ClickTale', 'category': 'Analytics', 'color': '#333333', 'icon': 'bar-chart'},
    {'name': 'Microsoft Advertising', 'category': 'Advertising', 'color': '#0078d4', 'icon': 'bar-chart'},

    # === Tag Managers ===
    {'name': 'Google Tag Manager', 'category': 'Tag managers', 'color': '#246fdb', 'icon': 'bar-chart'},
    {'name': 'Adobe Experience Platform Launch', 'category': 'Tag managers', 'color': '#ff0000', 'icon': 'bar-chart'},

    # === JavaScript Libraries ===
    {'name': 'jQuery', 'category': 'JavaScript libraries', 'color': '#0769ad', 'icon': 'file-code'},
    {'name': 'lit-html', 'category': 'JavaScript libraries', 'color': '#324fff', 'icon': 'file-code'},
    {'name': 'lit-element', 'category': 'JavaScript libraries', 'color': '#324fff', 'icon': 'file-code'},
    {'name': 'core-js', 'category': 'JavaScript libraries', 'color': '#333333', 'icon': 'file-code'},
    {'name': 'LazySizes', 'category': 'JavaScript libraries', 'color': '#00d1b2', 'icon': 'file-code'},
    {'name': 'Bootstrap', 'category': 'UI frameworks', 'color': '#7952b3', 'icon': 'layout'},
    {'name': 'Tailwind CSS', 'category': 'UI frameworks', 'color': '#06b6d4', 'icon': 'layout'},

    # === CDNs & Cloud ===
    {'name': 'Cloudflare', 'category': 'CDN', 'color': '#f38020', 'icon': 'cloud'},
    {'name': 'Akamai', 'category': 'CDN', 'color': '#009bde', 'icon': 'cloud'},
    {'name': 'Amazon Web Services', 'category': 'PaaS', 'color': '#ff9900', 'icon': 'cloud'},
    {'name': 'Microsoft Azure', 'category': 'PaaS', 'color': '#0078d4', 'icon': 'cloud'},
]

# Master Signatures for forensic detection
TECH_SIGNATURES = {
    'Adobe Experience Manager': {'headers': ['server:aem dispatcher'], 'body': ['/etc.clientlibs/', '/content/dam/', 'aem-grid'], 'meta': [{'name': 'generator', 'content': 'adobe experience manager'}]},
    'Microsoft Clarity': {'headers': [], 'body': ['clarity.js', 'www.clarity.ms', 'clarity/tag'], 'meta': []},
    'Hotjar': {'headers': [], 'body': ['static.hotjar.com', 'hj(', '_hjincluded'], 'meta': []},
    'Facebook Pixel': {'headers': [], 'body': ['connect.facebook.net/en_us/fbevents.js', 'fbq('], 'meta': []},
    'LinkedIn Insight Tag': {'headers': [], 'body': ['snap.licdn.com/li.lms-analytics', '_linkedin_partner_id'], 'meta': []},
    'comScore': {'headers': [], 'body': ['scorecardresearch.com/beacon.js'], 'meta': []},
    'Contentsquare': {'headers': [], 'body': ['contentsquare.net', 'contentsquare.com'], 'meta': []},
    'ClickTale': {'headers': [], 'body': ['clicktale.net', 'clicktale.js'], 'meta': []},
    'Microsoft Advertising': {'headers': [], 'body': ['bat.bing.com/bat.js', 'msclkid'], 'meta': []},
    'Adobe Experience Platform Launch': {'headers': [], 'body': ['assets.adobedtm.com'], 'meta': []},
    'lit-html': {'headers': [], 'body': ['lit-html'], 'meta': []},
    'lit-element': {'headers': [], 'body': ['lit-element'], 'meta': []},
    'core-js': {'headers': [], 'body': ['core-js'], 'meta': []},
    'LazySizes': {'headers': [], 'body': ['lazysizes.min.js', 'lazysizes.js'], 'meta': []},
    
    # Existing core
    'WordPress': {'headers': ['x-pingback:'], 'body': ['wp-content', 'wp-includes'], 'meta': [{'name': 'generator', 'content': 'wordpress'}]},
    'Shopify': {'headers': ['x-shopify-stage:'], 'body': ['cdn.shopify.com', 'shopify-section'], 'meta': []},
    'React': {'headers': [], 'body': ['react.js', '__NEXT_DATA__', 'data-reactroot'], 'meta': []},
    'Next.js': {'headers': ['x-powered-by:next.js'], 'body': ['__NEXT_DATA__', '_next/static'], 'meta': []},
    'Cloudflare': {'headers': ['server:cloudflare', 'cf-ray:'], 'body': ['cloudflare.com'], 'meta': []},
    'Akamai': {'headers': ['server:akamaighost', 'x-akamai-transformed:'], 'body': ['akamai.net'], 'meta': []},
    'Google Tag Manager': {'headers': [], 'body': ['googletagmanager.com/gtm.js'], 'meta': []},
}

_TECH_MAP = {t['name']: t for t in TECH_WATCHLIST}

'''def detect_technologies(domain, deep_scan=False):
    """Hybrid detection: Fast Static (requests) + Optional Forensic (Playwright)."""
    detected_list = []
    seen = set()
    
    # 1. Get Base Evidence (Static results)
    try:
        resp = safe_requests_get(f'https://{domain}', timeout=12)
        source_html = resp.text
        headers_str = "\n".join([f"{k}:{v}" for k, v in resp.headers.items()]).lower()
    except:
        source_html = ""
        headers_str = ""
        resp = None

    # 2. Forensic Render (Deep Scan)
    render_data = None
    if deep_scan:
        print(f"Executing Deep Forensic Scan for {domain}...")
        render_data = run_deep_scan(f"https://{domain}")
        if render_data['html']:
            source_html = render_data['html'] # Use fully rendered HTML for analysis

    content_lower = source_html.lower()

    # 3. Manual Fingerprinting
    for name, sigs in TECH_SIGNATURES.items():
        found = False
        evidence = ""
        
        # Check Rendered Variables first (High confidence)
        if render_data and name.lower() in render_data.get('variables', {}):
             found = True
             evidence = "JavaScript Variable Identified"

        # Check Headers
        if not found:
            for h in sigs['headers']:
                if h.lower() in headers_str:
                    found = True
                    evidence = f"HTTP Header: {h}"
                    break
        
        # Check Body (Rendered or Static)
        if not found:
            for b in sigs['body']:
                if b.lower() in content_lower:
                    found = True
                    evidence = f"Signature Found in Source"
                    break
        
        # Check Meta
        if not found:
            for m in sigs['meta']:
                if f'name="{m["name"].lower()}"' in content_lower and f'content="{m["content"].lower()}"' in content_lower:
                    found = True
                    evidence = f"Meta Tag: {m['name']}"
                    break

        if found:
            master = _TECH_MAP.get(name)
            seen.add(name.lower())
            detected_list.append({
                'name': name,
                'category': master['category'] if master else 'Miscellaneous',
                'color': master['color'] if master else 'var(--cyan)',
                'icon': master['icon'] if master else 'layout',
                'detected': True,
                'version': '',
                'evidence': evidence
            })

    # 4. Wappalyzer breadth
    if resp or (render_data and render_data['html']):
        webpage = WebPage.new_from_response(resp) if resp else WebPage.new(url=f"https://{domain}", html=source_html)
        wapp_results = _wappalyzer.analyze_with_categories(webpage)
        
        for name, info in wapp_results.items():
            if name.lower() in seen: continue
            seen.add(name.lower())
            categories = info.get('categories', [])
            category = categories[0] if categories else 'Miscellaneous'
            master = _TECH_MAP.get(name)
            
            detected_list.append({
                'name': name,
                'category': master['category'] if master else category,
                'color': master['color'] if master else 'var(--cyan)',
                'icon': master['icon'] if master else 'layout',
                'detected': True,
                'version': info.get('version', '') or '',
                'evidence': 'Detected via Wappalyzer Signature'
            })

    # 5. Build Not Detected
    not_detected_list = []
    for tech in TECH_WATCHLIST:
        if tech['name'].lower() not in seen:
            not_detected_list.append({**tech, 'detected': False, 'version': '', 'evidence': ''})

    detected_list.sort(key=lambda x: x['category'])
    return {
        'detected': detected_list,
        'not_detected': not_detected_list,
        'counts': {'detected': len(detected_list), 'not_detected': len(not_detected_list)}
    }'''

    def detect_technologies(domain):
    return {
        "status": "Technology detection temporarily disabled"
    }
