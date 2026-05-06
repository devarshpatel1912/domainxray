''' from flask import Flask, render_template, request, jsonify, send_file
from config import Config
from domain_scanner.whois_lookup import lookup_whois
from domain_scanner.dns_lookup import lookup_dns, get_ip_addresses
from domain_scanner.subdomain_scanner import scan_subdomains
from domain_scanner.ssl_checker import check_ssl
from domain_scanner.ip_lookup import lookup_ip
from domain_scanner.security_checker import check_security
from domain_scanner.tech_detector import detect_technologies
from domain_scanner.history_tracker import build_history
from domain_scanner.threat_intel import analyze_threats
from domain_scanner.monitoring import get_monitoring_data
import html as html_std
from domain_scanner.utils import clean_domain_name as clean_domain, safe_requests_get
from domain_scanner.tools import (
    check_ports, get_http_headers, check_usernames, 
    reverse_ip_lookup, lookup_emails
) 
import re
import datetime
import io
import os
from fpdf import FPDF

app = Flask(__name__)
app.config.from_object(Config)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form.get('domain', '').strip()
    if not domain:
        return render_template('index.html', error='Please enter a domain name')
    
    domain = clean_domain(domain)
    
    # Validate domain format
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
        return render_template('index.html', error='Invalid domain format')
    
    return render_template('results.html', domain=domain)


@app.route('/api/scan/overview/<domain>')
def api_overview(domain):
    """API endpoint for overview data (WHOIS + IP + SSL)."""
    domain = clean_domain(domain)
    
    # WHOIS data
    whois_data = lookup_whois(domain)
    
    # IP addresses
    ipv4, ipv6 = get_ip_addresses(domain)
    
    # IP geolocation
    ip_info = lookup_ip(ipv4) if ipv4 else {}
    
    # SSL certificate
    ssl_info = check_ssl(domain)
    
    return jsonify({
        'whois': whois_data,
        'ip': {
            'ipv4': ipv4,
            'ipv6': ipv6,
            'info': ip_info
        },
        'ssl': ssl_info
    })


@app.route('/api/scan/dns/<domain>')
def api_dns(domain):
    """API endpoint for DNS records."""
    domain = clean_domain(domain)
    records = lookup_dns(domain)
    return jsonify({'records': records, 'total': len(records)})


@app.route('/api/scan/subdomains/<domain>')
def api_subdomains(domain):
    """API endpoint for subdomain scanning."""
    domain = clean_domain(domain)
    result = scan_subdomains(
        domain,
        app.config['SUBDOMAIN_WORDLIST'],
        max_threads=app.config['SUBDOMAIN_THREADS'],
        timeout=app.config['SUBDOMAIN_TIMEOUT']
    )
    return jsonify(result)


@app.route('/api/scan/security/<domain>')
def api_security(domain):
    """API endpoint for security checks."""
    domain = clean_domain(domain)
    ssl_info = check_ssl(domain)
    result = check_security(domain, ssl_info)
    return jsonify(result)


@app.route('/api/scan/history/<domain>')
def api_history(domain):
    """API endpoint for domain history."""
    domain = clean_domain(domain)
    whois_data = lookup_whois(domain)
    ssl_data = check_ssl(domain)
    result = build_history(whois_data, ssl_data)
    return jsonify(result)


@app.route('/api/scan/techstack/<domain>')
def api_techstack(domain):
    """API endpoint for technology stack detection."""
    domain = clean_domain(domain)
    is_deep = request.args.get('deep', 'false').lower() == 'true'
    result = detect_technologies(domain, deep_scan=is_deep)
    return jsonify(result)


@app.route('/api/scan/threatintel/<domain>')
def api_threatintel(domain):
    """API endpoint for threat intelligence."""
    domain = clean_domain(domain)
    # Get security data to feed into reputation scoring
    ssl_info = check_ssl(domain)
    security_data = check_security(domain, ssl_info)
    result = analyze_threats(domain, security_data)
    return jsonify(result)


@app.route('/api/scan/monitoring/<domain>')
def api_monitoring(domain):
    """API endpoint for monitoring data."""
    domain = clean_domain(domain)
    result = get_monitoring_data(domain)
    return jsonify(result)


def _parse_html_title(body):
    m = re.search(r'<title[^>]*>([^<]*)</title>', body, re.I | re.DOTALL)
    if not m:
        return None
    t = re.sub(r'\s+', ' ', m.group(1)).strip()
    t = html_std.unescape(t)
    return t[:500] if t else None


def _parse_html_meta_description(body):
    patterns = (
        r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\'>]*)["\']',
        r'<meta[^>]+content=["\']([^"\'>]*)["\'][^>]+name=["\']description["\']',
        r'<meta[^>]+property=["\']og:description["\'][^>]+content=["\']([^"\'>]*)["\']',
        r'<meta[^>]+content=["\']([^"\'>]*)["\'][^>]+property=["\']og:description["\']',
    )
    for pat in patterns:
        m = re.search(pat, body, re.I)
        if m:
            s = html_std.unescape(m.group(1).strip())
            return s[:800] if s else None
    return None


@app.route('/api/scan/site-identity/<domain>')
def api_site_identity(domain):
    """Fetch public homepage HTML and extract title + meta description."""
    domain = clean_domain(domain)
    if not domain:
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400

    timeout = app.config.get('HTTP_TIMEOUT', 10)
    last_err = None
    for scheme in ('https', 'http'):
        url = f'{scheme}://{domain}'
        try:
            resp = safe_requests_get(url, timeout=timeout, allow_redirects=True)
            body = resp.text[:800000]
            return jsonify({
                'ok': True,
                'final_url': resp.url,
                'http_status': resp.status_code,
                'title': _parse_html_title(body),
                'meta_description': _parse_html_meta_description(body),
            })
        except Exception as e:
            last_err = str(e)
            continue

    return jsonify({
        'ok': False,
        'error': last_err or 'Could not fetch homepage',
        'title': None,
        'meta_description': None,
    })


@app.route('/api/scan/ai-insights/<domain>')
def api_ai_insights(domain):
    """API endpoint for AI-powered insights."""
    domain = clean_domain(domain)

    # Gather data from multiple sources
    ssl_info = check_ssl(domain)
    security_data = check_security(domain, ssl_info)
    whois_data = lookup_whois(domain)

    # Build AI insights from aggregated data
    insights = _build_ai_insights(domain, security_data, ssl_info, whois_data)
    return jsonify(insights)


def _build_ai_insights(domain, security_data, ssl_info, whois_data):
    """Generate AI-powered insights from security and domain data."""
    score = security_data.get('score', 50)
    checks = security_data.get('checks', [])
    failed_checks = [c for c in checks if c['status'] == 'fail']
    warning_checks = [c for c in checks if c['status'] == 'warning']

    # Risk level
    if score >= 80:
        risk_level = 'Low Risk'
        risk_class = 'low'
    elif score >= 50:
        risk_level = 'Medium Risk'
        risk_class = 'medium'
    else:
        risk_level = 'High Risk'
        risk_class = 'high'

    # Build risk summary
    ssl_status = 'valid SSL/TLS encryption' if ssl_info.get('valid') else 'invalid SSL certificate'
    has_spf = any(c['name'] == 'SPF Record' and c['status'] == 'pass' for c in checks)
    email_auth = 'and proper email authentication in place' if has_spf else 'but missing email authentication'

    summary = (
        f"{domain} maintains a {'generally healthy' if score >= 60 else 'concerning'} security posture with a "
        f"{risk_level} score of {score}/100. The domain has {ssl_status} {email_auth}."
    )

    if failed_checks:
        summary += f" However, {len(failed_checks)} critical {'issue needs' if len(failed_checks) == 1 else 'issues need'} to be addressed."

    # Key issues
    key_issues = []
    for check in failed_checks[:4]:
        severity = 'high' if check.get('weight', 0) >= 12 else 'medium'
        issue_text = f"{check['name']} — {check['description']}"
        if 'port' in check['description'].lower():
            issue_text += ' — high exploitation risk'
        elif 'hsts' in check['name'].lower():
            issue_text += ' — allows potential HTTPS downgrade attacks'
        elif 'csp' in check['name'].lower():
            issue_text += ' — XSS vulnerabilities possible'
        key_issues.append({'text': issue_text, 'severity': severity})

    for check in warning_checks[:2]:
        key_issues.append({
            'text': f"{check['name']} — {check['description']}",
            'severity': 'low'
        })

    # Recommendations
    recommendations = []
    for check in failed_checks:
        if 'port' in check['name'].lower():
            reco = f"Immediately firewall exposed ports — use SSH tunneling or VPN for access"
        elif 'hsts' in check['name'].lower():
            reco = f"Add Strict-Transport-Security header with a minimum 1-year max-age"
        elif 'csp' in check['name'].lower():
            reco = f"Configure a Content Security Policy to prevent cross-site scripting"
        elif 'ssl' in check['name'].lower():
            days = ssl_info.get('days_remaining', 0)
            reco = f"Set up automated SSL renewal to prevent expiry in {days} days"
        elif 'x-frame' in check['name'].lower():
            reco = f"Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking"
        elif 'dmarc' in check['name'].lower():
            reco = f"Implement DMARC with p=reject policy to prevent email spoofing"
        elif 'spf' in check['name'].lower():
            reco = f"Add an SPF record to authorize legitimate mail senders"
        else:
            reco = f"Address: {check['name']} — {check['description']}"
        recommendations.append(reco)

    generated_time = datetime.datetime.now().strftime("%B %d, %Y at %H:%M")
    return {
        'risk_level': risk_level,
        'risk_class': risk_class,
        'score': score,
        'summary': summary,
        'key_issues': key_issues,
        'recommendations': recommendations,
        'generated_at': generated_time
    }


# ============================================
# Utility Tools Endpoints
# ============================================

@app.route('/api/tool/whois/<domain>')
def tool_whois(domain):
    domain = clean_domain(domain)
    data = lookup_whois(domain)
    # Convert WHOIS dict to string-like output for the tool terminal
    output = f"WHOIS Lookup for {domain}\n"
    output += "-" * 40 + "\n"
    output += f"Registrar: {data.get('registrar', 'Unknown')}\n"
    output += f"Created: {data.get('creation_date_formatted', 'N/A')}\n"
    output += f"Expires: {data.get('expiration_date_formatted', 'N/A')}\n"
    output += f"Last Updated: {data.get('updated_date_formatted', 'N/A')}\n"
    
    ns = data.get('nameservers', [])
    if ns:
        output += f"Nameservers:\n"
        for s in ns:
            output += f"  - {s}\n"
            
    output += f"Status: {'Active' if data.get('is_active') else 'Inactive'}\n"
    return jsonify({'output': output})

@app.route('/api/tool/ports/<target>')
def tool_ports(target):
    output = check_ports(target)
    return jsonify({'output': output})

@app.route('/api/tool/headers')
def tool_headers():
    url = request.args.get('url')
    if not url: return jsonify({'error': 'URL required'}), 400
    output = get_http_headers(url)
    return jsonify({'output': output})

@app.route('/api/tool/usernames/<username>')
def tool_usernames(username):
    output = check_usernames(username)
    return jsonify({'output': output})

@app.route('/api/tool/reverse_ip/<ip>')
def tool_reverse_ip(ip):
    output = reverse_ip_lookup(ip)
    return jsonify({'output': output})

@app.route('/api/tool/emails/<domain>')
def tool_emails(domain):
    domain = clean_domain(domain)
    output = lookup_emails(domain)
    return jsonify({'output': output})


# ============================================
# PDF Export Generation
# ============================================

class PDFReport(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42) # Dark navy
        self.rect(0, 0, 210, 40, 'F')
        self.set_y(12)
        self.set_font('helvetica', 'B', 24)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, 'DomainXray Report', ln=True, align='C')
        self.set_font('helvetica', '', 10)
        self.set_text_color(165, 180, 252)
        self.cell(0, 10, 'Comprehensive Domain Intelligence & Security Analysis', ln=True, align='C')

    def footer(self):
        self.set_y(-15)
        self.set_font('helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()} | Generated by DomainXray | {datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}', 0, 0, 'C')

    def section_header(self, title):
        self.set_font('helvetica', 'B', 16)
        self.set_text_color(15, 23, 42)
        self.ln(10)
        self.cell(0, 10, title, ln=True)
        self.line(self.get_x(), self.get_y(), self.get_x() + 190, self.get_y())
        self.ln(5)

@app.route('/api/export/pdf', methods=['POST'])
def export_pdf():
    try:
        data = request.get_json(silent=True) or {}
        domain = clean_domain((data.get('domain') or '').strip())
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        sections = data.get('sections', [])
        if not isinstance(sections, list):
            sections = []
        
        pdf = PDFReport()
        pdf.add_page()
        
        pdf.set_y(45)
        pdf.set_font('helvetica', 'B', 14)
        pdf.cell(0, 10, f'Analysis Target: {domain}', ln=True)
        pdf.set_font('helvetica', '', 11)
        pdf.cell(0, 10, f'Generated On: {datetime.datetime.now().strftime("%B %d, %Y at %H:%M:%S")}', ln=True)
        
        # --- Overview Section ---
        if 'overview' in sections:
            pdf.section_header('Domain Overview')
            whois = lookup_whois(domain)
            ipv4, _ = get_ip_addresses(domain)
            ip_info = lookup_ip(ipv4) if ipv4 else {}
            
            # Domain details
            reg = whois.get('registrant', {})
            registrant_addr = ", ".join(filter(None, [reg.get('city'), reg.get('state'), reg.get('country')])) or "Private"

            pdf.set_font('helvetica', 'B', 11)
            summary_data = [
                ('Registrar', whois.get('registrar', 'Unknown')),
                ('Registrant Org', reg.get('organization', 'Unknown')),
                ('Business Address', registrant_addr),
                ('Created', whois.get('creation_date_formatted', 'N/A')),
                ('Expires', whois.get('expiration_date_formatted', 'N/A')),
                ('IP Address', ipv4 or 'N/A'),
                ('Hosting', ip_info.get('hosting', 'Unknown'))
            ]
            
            for label, val in summary_data:
                pdf.set_font('helvetica', 'B', 10)
                pdf.cell(40, 7, f'{label}:', 0)
                pdf.set_font('helvetica', '', 10)
                pdf.cell(0, 7, str(val), 0, True)

        # --- DNS Section ---
        if 'dns' in sections:
            pdf.section_header('DNS Infrastructure')
            records = lookup_dns(domain)
            pdf.set_font('helvetica', 'B', 10)
            pdf.cell(20, 8, 'Type', 1)
            pdf.cell(60, 8, 'Name', 1)
            pdf.cell(90, 8, 'Value', 1)
            pdf.cell(20, 8, 'TTL', 1, True)
            
            pdf.set_font('helvetica', '', 9)
            for r in records[:30]: # Cap to prevent huge files
                pdf.cell(20, 7, str(r['type']), 1)
                pdf.cell(60, 7, str(r['name']), 1)
                pdf.cell(90, 7, str(r['value'][:50]), 1)
                pdf.cell(20, 7, str(r['ttl']), 1, True)

        # --- Security Section ---
        if 'security' in sections:
            pdf.section_header('Security & SSL Forensics')
            ssl_info = check_ssl(domain)
            sec_data = check_security(domain, ssl_info)
            
            # Highlight SSL Grade
            pdf.set_font('helvetica', 'B', 12)
            pdf.cell(95, 10, f"Overall Security Score: {sec_data['score']}/100")
            pdf.cell(95, 10, f"SSL Security Grade: {ssl_info.get('grade', 'N/A')}", ln=True)
            pdf.set_font('helvetica', 'I', 9)
            pdf.cell(0, 7, f"Certificate Status: {'Valid' if ssl_info.get('valid') else 'Invalid/Warning'}", ln=True)
            pdf.ln(2)
            
            pdf.set_font('helvetica', 'B', 10)
            pdf.cell(80, 8, 'Security Control', 1)
            pdf.cell(30, 8, 'Result', 1)
            pdf.cell(80, 8, 'Description', 1, True)
            
            pdf.set_font('helvetica', '', 9)
            for check in sec_data.get('checks', []):
                status_text = 'PASSED' if check['status'] == 'pass' else 'FAILED' if check['status'] == 'fail' else 'WARNING'
                pdf.cell(80, 7, str(check['name']), 1)
                pdf.cell(30, 7, status_text, 1)
                pdf.cell(80, 7, str(check['description']), 1, True)

        # --- Tech Stack Section ---
        if 'techstack' in sections:
            pdf.section_header('Technology Intelligence')
            tech_data = detect_technologies(domain)
            detected = tech_data.get('detected', [])
            
            if detected:
                for tech in detected:
                    pdf.set_font('helvetica', 'B', 10)
                    pdf.cell(0, 7, f"• {tech['name']} ({tech['category']})", ln=True)
                    pdf.set_font('helvetica', 'I', 9)
                    pdf.cell(0, 5, f"  Evidence: {tech.get('evidence', 'General fingerprinting')}", ln=True)
                    pdf.ln(2)
            else:
                pdf.cell(0, 7, 'No significant technology fingerprints detected.', ln=True)

        buffer = io.BytesIO()
        pdf_output = pdf.output()
        buffer.write(bytes(pdf_output))
        buffer.seek(0)
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=f"{domain}_DomainXray_Report.pdf",
            mimetype='application/pdf'
        )
    except Exception as e:
        print(f"PDF Export Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500



@app.route('/api/compare/<domain1>/<domain2>')
def api_compare(domain1, domain2):
    """API endpoint for domain comparison."""
    domain1 = clean_domain(domain1)
    domain2 = clean_domain(domain2)

    def _gather_domain_data(domain):
        """Collect comparison data for a single domain."""
        whois_data = lookup_whois(domain)
        ipv4, ipv6 = get_ip_addresses(domain)
        ip_info = lookup_ip(ipv4) if ipv4 else {}
        ssl_info = check_ssl(domain)
        security_data = check_security(domain, ssl_info)
        tech_data = detect_technologies(domain)

        # Count open ports from security checks
        open_ports = 0
        for c in security_data.get('checks', []):
            if 'port' in c.get('name', '').lower() and c['status'] == 'fail':
                desc = c.get('description', '')
                # Extract port numbers from description
                import re as _re
                ports = _re.findall(r'\d+', desc)
                open_ports = len(ports) if ports else 1

        detected_techs = tech_data.get('detected', [])
        tech_names = [t['name'] for t in detected_techs[:5]]

        return {
            'domain': domain,
            'score': security_data.get('score', 0),
            'risk_level': security_data.get('risk_level', 'Unknown'),
            'status': 'Active' if whois_data.get('is_active') else 'Expired',
            'domain_age': whois_data.get('domain_age', 'N/A'),
            'registrar': whois_data.get('registrar', 'Unknown'),
            'expires': whois_data.get('expiration_date_formatted', 'N/A'),
            'ip_address': ipv4 or 'N/A',
            'hosting': ip_info.get('hosting', 'Unknown'),
            'ssl_status': 'Valid' if ssl_info.get('valid') else 'Invalid',
            'ssl_days': ssl_info.get('days_remaining', 0),
            'ssl_issuer': ssl_info.get('issuer', 'Unknown'),
            'ssl_algorithm': ssl_info.get('algorithm', 'N/A'),
            'open_ports': open_ports,
            'tech_stack': tech_names
        }

    data1 = _gather_domain_data(domain1)
    data2 = _gather_domain_data(domain2)

    return jsonify({'domain1': data1, 'domain2': data2})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000))) '''


from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "DomainXray Running Successfully"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)