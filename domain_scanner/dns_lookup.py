import dns.resolver
import dns.rdatatype
import ipaddress
import socket
from .utils import clean_domain_name, get_dns_resolver


def lookup_dns(domain):
    """Fetch all important DNS records for a domain with hybrid system/fallback logic."""
    domain = clean_domain_name(domain)
    records = []
    # Expanded list of important record types
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'CAA', 'SRV', 'DS', 'DNSKEY']
    
    system_resolver = get_dns_resolver()
    fallback_resolver = dns.resolver.Resolver()
    fallback_resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    fallback_resolver.timeout = 3
    fallback_resolver.lifetime = 6

    for rtype in record_types:
        success = False
        for resolver in [system_resolver, fallback_resolver]:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    record = {
                        'type': rtype,
                        'name': domain,
                        'value': '',
                        'ttl': answers.rrset.ttl,
                        'status': 'Active'
                    }
                    
                    if rtype == 'A' or rtype == 'AAAA':
                        record['value'] = rdata.address
                    elif rtype == 'MX':
                        record['value'] = f"{rdata.preference} {rdata.exchange}"
                    elif rtype == 'TXT':
                        record['value'] = ' '.join([s.decode('utf-8', errors='replace') if isinstance(s, bytes) else s for s in rdata.strings])
                    elif rtype == 'CNAME' or rtype == 'NS':
                        record['value'] = str(rdata.target)
                    elif rtype == 'SOA':
                        record['value'] = f"{rdata.mname} {rdata.rname} (Serial: {rdata.serial})"
                    elif rtype == 'CAA':
                        record['value'] = f'{rdata.flags} {rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag} "{rdata.value}"'
                    elif rtype == 'SRV':
                        record['value'] = f"{rdata.priority} {rdata.weight} {rdata.port} {rdata.target}"
                    elif rtype == 'DS':
                        record['value'] = f"{rdata.key_tag} {rdata.algorithm} {rdata.digest_type} {rdata.digest.hex().upper()}"
                    elif rtype == 'DNSKEY':
                        record['value'] = f"{rdata.flags} {rdata.protocol} {rdata.algorithm} [Key Data]"
                    else:
                        record['value'] = str(rdata)
                    
                    records.append(record)
                success = True
                break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.Timeout):
                continue
            except Exception:
                continue
        
        if rtype == 'A' and not success:
            try:
                ip = socket.gethostbyname(domain)
                records.append({
                    'type': 'A', 'name': domain, 'value': ip, 'ttl': 3600, 'status': 'Active'
                })
            except: pass
    
    # Check for DMARC record at _dmarc.domain
    for resolver in [system_resolver, fallback_resolver]:
        try:
            dmarc_domain = f'_dmarc.{domain}'
            answers = resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                value = ' '.join([s.decode('utf-8', errors='replace') if isinstance(s, bytes) else s for s in rdata.strings])
                records.append({
                    'type': 'TXT', 'name': dmarc_domain, 'value': value, 'ttl': answers.rrset.ttl, 'status': 'Active'
                })
            break
        except: continue
    
    return records


def get_ip_addresses(domain):
    """Get IPv4 and IPv6 addresses for a domain."""
    domain = clean_domain_name(domain)
    ipv4_list = set()
    ipv6_list = set()
    
    resolver = get_dns_resolver()

    try:
        answers = resolver.resolve(domain, 'A')
        for answer in answers:
            ipv4_list.add(answer.address)
    except Exception:
        pass

    try:
        answers = resolver.resolve(domain, 'AAAA')
        for answer in answers:
            ipv6_list.add(answer.address)
    except Exception:
        pass

    # Fallback to system resolver to avoid empty/wrong DNS server edge-cases.
    if not ipv4_list and not ipv6_list:
        try:
            info = socket.getaddrinfo(domain, None)
            for entry in info:
                address = entry[4][0]
                try:
                    parsed = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if parsed.version == 4:
                    ipv4_list.add(address)
                else:
                    ipv6_list.add(address)
        except Exception:
            pass

    ipv4_sorted = sorted(ipv4_list, key=lambda ip: tuple(int(part) for part in ip.split('.')))
    ipv6_sorted = sorted(ipv6_list)

    ipv4 = ipv4_sorted[0] if ipv4_sorted else None
    ipv6 = ipv6_sorted[0] if ipv6_sorted else None

    return ipv4, ipv6
