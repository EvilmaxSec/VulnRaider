#!/usr/bin/env python3
"""VulnRaider - CLI vulnerability scanner for web and systems."""

import argparse
import datetime
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 500, 514, 587, 631, 993, 995, 1080,
    1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2375, 2376, 3000, 3306,
    3389, 5000, 5432, 5900, 5985, 5986, 6379, 7001, 8000, 8080, 8081, 8443,
    8888, 9000, 9200, 9300, 11211, 27017,
]
COMMON_PATHS = [
    '/.git/',
    '/.git/config',
    '/.svn/',
    '/.hg/',
    '/.env',
    '/.env.bak',
    '/.env.backup',
    '/.env.old',
    '/.env.save',
    '/config.php',
    '/config.php.bak',
    '/config.php.old',
    '/config.php.save',
    '/config.bak',
    '/config.old',
    '/config.json',
    '/config.yml',
    '/phpinfo.php',
    '/admin/',
    '/administrator/',
    '/dashboard/',
    '/login/',
    '/cpanel/',
    '/robots.txt',
    '/server-status',
    '/wp-login.php',
    '/xmlrpc.php',
    '/wp-config.php.bak',
    '/wp-config.php.old',
    '/backup/',
    '/backups/',
    '/backup.zip',
    '/backup.tar.gz',
    '/backup.sql',
    '/database.sql',
    '/db.sql',
    '/dump.sql',
    '/site.zip',
    '/www.zip',
    '/public.zip',
    '/app.zip',
    '/source.zip',
    '/debug.log',
    '/error.log',
    '/access.log',
    '/.DS_Store',
    '/composer.json',
    '/package.json',
    '/yarn.lock',
    '/id_rsa',
    '/id_rsa.pub',
]
COMMON_SUBDOMAINS = [
    'www', 'mail', 'webmail', 'smtp', 'pop', 'imap', 'ftp', 'sftp', 'ssh', 'vpn',
    'api', 'dev', 'test', 'stage', 'staging', 'beta', 'demo', 'portal', 'admin',
    'panel', 'cpanel', 'dashboard', 'secure', 'login', 'auth', 'sso', 'app',
    'apps', 'm', 'mobile', 'cdn', 'static', 'assets', 'img', 'images', 'media',
    'files', 'download', 'docs', 'help', 'support', 'status', 'monitor',
    'grafana', 'jenkins', 'git', 'gitlab', 'repo', 'backup', 'db', 'mysql',
    'postgres', 'redis', 'old', 'new', 'blog', 'shop', 'store',
]

IP_GEO_API = 'http://ip-api.com/json/'
VERBOSE = False

def print_logo():
    logo = f'''
{Colors.MAGENTA}{Colors.BOLD}.-.   .-..-. .-.,-.    .-. .-.,---.    .--.  ,-. ,'|"\\   ,---.  ,---.
 \\ \\ / / | | | || |    |  \\| || .-.\\  / /\\ \\ |(| | |\\ \\  | .-'  | .-.\\
  \\ V /  | | | || |    |   | || `-'/ / /__\\ \\(_) | | \\ \\ | `-.  | `-'/
   ) /   | | | || |    | |\\  ||   (  |  __  || | | |  \\ \\| .-'  |   (
  (_)    | `-')|| `--. | | |)|| |\\ \\ | |  |)|| | /(|`-' /|  `--.| |\\ \\
         `---(_)|( __.'/(  (_)|_| \\)\\|_|  (_)`-'(__)`--' /( __.'|_| \\)\\
                (_)   (__)        (__)                  (__)        (__)
{Colors.END}
{Colors.CYAN}{Colors.BOLD}Recon. Fingerprint. Expose. Secure.{Colors.END}
{Colors.YELLOW}Author: EvilmaxSec{Colors.END}
{Colors.YELLOW}GitHub: https://github.com/EvilmaxSec{Colors.END}
{Colors.RED}{Colors.BOLD}[!] WARNING: Use this tool only on systems you own or have explicit permission to test!{Colors.END}
{Colors.RED}{Colors.BOLD}[!] Unauthorized access is illegal. The author is not responsible for misuse.{Colors.END}
'''
    print(logo)

def parse_args():
    parser = argparse.ArgumentParser(
        description='VulnRaider - scan web and network targets and produce vulnerability findings.',
        epilog='Example: python3 VulnRaider.py -t example.com -o report.txt --json report.json --ports 80,443,8080'
    )
    parser.add_argument('-t', '--target', required=True, help='Target IP address or URL/domain to scan.')
    parser.add_argument('-o', '--output', help='Text report output file. If not specified, report will only be displayed.')
    parser.add_argument('--json', dest='json_output', help='Optional JSON output file.')
    parser.add_argument('--ports', help='Comma-separated ports to scan. Default common ports.', default=','.join(str(p) for p in COMMON_PORTS))
    parser.add_argument('--timeout', type=float, default=3.0, help='Socket timeout in seconds.')
    parser.add_argument('--geo', action='store_true', help='Attempt IP geolocation for the target.')
    parser.add_argument('--web-only', action='store_true', help='Skip port scan and only run web analysis.')
    parser.add_argument('--no-ssl', action='store_true', help='Skip HTTPS certificate checks.')
    parser.add_argument('--verbose', action='store_true', help='Print scan progress details.')
    return parser.parse_args()


def debug(message):
    if VERBOSE:
        print(f'{Colors.BLUE}[*]{Colors.END} {message}')


def strip_colors(text):
    return re.sub(r'\033\[[0-9;]*m', '', text)


def normalize_target(target):
    text = target.strip()
    if text.startswith('http://') or text.startswith('https://'):
        parsed = urllib.parse.urlparse(text)
        hostname = parsed.hostname
    else:
        hostname = text
    return hostname


def normalize_web_target(target, hostname):
    text = target.strip()
    if text.startswith('http://') or text.startswith('https://'):
        parsed = urllib.parse.urlparse(text)
        return parsed.netloc or hostname
    return hostname


def resolve_target(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None


def is_ip_address(hostname):
    try:
        socket.inet_aton(hostname)
        return hostname.count('.') == 3
    except OSError:
        return False


def discover_subdomains(hostname):
    if is_ip_address(hostname) or hostname in ('localhost',):
        return []

    found = []
    seen = set()
    for subdomain in COMMON_SUBDOMAINS:
        candidate = f'{subdomain}.{hostname}'
        debug(f'Checking subdomain {candidate}')
        try:
            _, _, addresses = socket.gethostbyname_ex(candidate)
        except socket.gaierror:
            continue

        ips = sorted(set(addresses))
        key = (candidate, tuple(ips))
        if ips and key not in seen:
            seen.add(key)
            found.append({'host': candidate, 'ips': ips})
    return found


def geo_lookup(ip):
    try:
        debug(f'Querying geolocation for {ip}')
        url = IP_GEO_API + urllib.parse.quote(ip)
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get('status') == 'success':
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'), 
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                }
    except Exception:
        return None
    return None


def scan_ports(ip, hostname, ports, timeout):
    findings = []
    for port in ports:
        debug(f'Scanning port {port}')
        try:
            service = guess_service(port)
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                service, version = detect_service(sock, hostname, port, service, timeout)
            findings.append({
                'port': port,
                'status': 'open',
                'service': service,
                'version': version or 'unknown',
            })
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return findings


def guess_service(port):
    common = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        69: 'TFTP',
        80: 'HTTP',
        111: 'RPC',
        123: 'NTP',
        135: 'MSRPC',
        137: 'NetBIOS',
        138: 'NetBIOS',
        139: 'NetBIOS',
        110: 'POP3',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP',
        389: 'LDAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        500: 'IPsec',
        514: 'Syslog',
        587: 'SMTP',
        631: 'IPP',
        993: 'IMAPS',
        995: 'POP3S',
        1080: 'SOCKS',
        1433: 'MSSQL',
        1521: 'Oracle',
        1723: 'PPTP',
        2049: 'NFS',
        2082: 'cPanel',
        2083: 'cPanel-SSL',
        2086: 'WHM',
        2087: 'WHM-SSL',
        2375: 'Docker',
        2376: 'Docker-TLS',
        3000: 'HTTP-dev',
        3306: 'MySQL',
        3389: 'RDP',
        5000: 'HTTP-dev',
        5432: 'PostgreSQL',
        5900: 'VNC',
        5985: 'WinRM',
        5986: 'WinRM-SSL',
        6379: 'Redis',
        7001: 'WebLogic',
        8000: 'HTTP-alt',
        8080: 'HTTP-alt',
        8081: 'HTTP-alt',
        8443: 'HTTPS-alt',
        8888: 'HTTP-alt',
        9000: 'HTTP-alt',
        9200: 'Elasticsearch',
        9300: 'Elasticsearch',
        11211: 'Memcached',
        27017: 'MongoDB',
    }
    return common.get(port, 'unknown')


def detect_service(sock, hostname, port, service, timeout):
    sock.settimeout(timeout)
    try:
        if service in ('HTTP', 'HTTP-alt', 'HTTP-dev', 'cPanel', 'WHM', 'WebLogic'):
            return service, http_server_header(sock, hostname, use_tls=False, timeout=timeout)
        if service in ('HTTPS', 'HTTPS-alt', 'cPanel-SSL', 'WHM-SSL'):
            return service, http_server_header(sock, hostname, use_tls=True, timeout=timeout)

        if service in ('SSH', 'FTP', 'SMTP', 'POP3', 'IMAP'):
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            return service, clean_banner(banner)

        if service == 'Telnet':
            sock.sendall(b'\r\n')
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            return service, clean_banner(banner)

        http_banner = http_server_header(sock, hostname, use_tls=False, timeout=timeout)
        if http_banner:
            return 'HTTP', http_banner
    except Exception as exc:
        debug(f'Banner probe failed for port {port}: {exc}')
    return service, None


def http_server_header(sock, hostname, use_tls, timeout):
    try:
        stream = sock
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            stream = context.wrap_socket(sock, server_hostname=hostname)
        request = f'HEAD / HTTP/1.0\r\nHost: {hostname}\r\nUser-Agent: VulnRaider/1.0\r\n\r\n'
        stream.sendall(request.encode('ascii'))
        response = stream.recv(1024).decode('iso-8859-1', errors='ignore')
        for line in response.splitlines():
            if line.lower().startswith('server:'):
                return clean_banner(line.split(':', 1)[1].strip())
        first_line = response.splitlines()[0] if response.splitlines() else ''
        return clean_banner(first_line)
    except Exception as exc:
        debug(f'HTTP version probe failed: {exc}')
    return None


def clean_banner(value):
    if not value:
        return None
    return ' '.join(value.replace('\r', ' ').replace('\n', ' ').split())[:120]


def build_header_data(header_items):
    headers = {}
    cookies = []
    for key, value in header_items:
        lower_key = key.lower()
        if lower_key == 'set-cookie':
            cookies.append(value)
        if lower_key in headers:
            headers[lower_key] = f'{headers[lower_key]}, {value}'
        else:
            headers[lower_key] = value
    return headers, cookies


def fetch_url(url, timeout, method='GET'):
    headers = {
        'User-Agent': 'VulnRaider/1.0',
    }
    request = urllib.request.Request(url, headers=headers, method=method)
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            response_headers, cookies = build_header_data(response.getheaders())
            return {
                'url': url,
                'final_url': response.geturl(),
                'code': response.getcode(),
                'headers': response_headers,
                'cookies': cookies,
                'body': response.read(4096).decode('utf-8', errors='ignore'),
            }
    except urllib.error.HTTPError as exc:
        response_headers, cookies = build_header_data(exc.headers.items() if exc.headers else [])
        return {
            'url': url,
            'final_url': getattr(exc, 'url', url),
            'code': exc.code,
            'headers': response_headers,
            'cookies': cookies,
            'body': exc.read(4096).decode('utf-8', errors='ignore'),
        }
    except urllib.error.URLError as exc:
        debug(f'Failed to fetch {url}: {exc}')
        return None
    except Exception as exc:
        debug(f'Unexpected error fetching {url}: {exc}')
        return None


def tls_certificate_info(hostname, timeout):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                }
    except Exception as exc:
        debug(f'TLS certificate check failed: {exc}')
        return None


def scan_web(web_host, timeout, no_ssl=False, tls_hostname=None):
    results = {'http': None, 'https': None, 'paths': [], 'tls': None, 'methods': {}}
    for scheme in ['http', 'https']:
        if scheme == 'https' and no_ssl:
            continue
        url = f'{scheme}://{web_host}/'
        debug(f'Fetching {url}')
        response = fetch_url(url, timeout)
        if response:
            results[scheme] = response
            methods = check_http_methods(url, timeout)
            if methods:
                results['methods'][scheme] = methods
    path_schemes = [scheme for scheme in ['https', 'http'] if results.get(scheme)]
    if not path_schemes:
        path_schemes = ['http']
    for path in COMMON_PATHS:
        for scheme in path_schemes:
            url = f'{scheme}://{web_host}{path}'
            debug(f'Checking path {url}')
            result = fetch_url(url, timeout)
            if result and result['code'] in (200, 403, 401, 500):
                results['paths'].append({'path': path, 'scheme': scheme, 'code': result['code'], 'url': url})
    if not no_ssl:
        results['tls'] = tls_certificate_info(tls_hostname or web_host, timeout)
    return results


def check_http_methods(url, timeout):
    response = fetch_url(url, timeout, method='OPTIONS')
    if not response:
        return []
    headers = response.get('headers', {})
    method_text = headers.get('allow') or headers.get('access-control-allow-methods') or ''
    methods = []
    for method in re.split(r'[\s,]+', method_text.upper()):
        if method and method.isalpha() and method not in methods:
            methods.append(method)
    return methods


def assess_vulnerabilities(target, ip, geo, port_findings, web_results):
    issues = []
    for port in port_findings:
        if port['service'] in ('FTP', 'Telnet', 'SMB', 'Docker', 'Redis', 'MongoDB', 'Memcached', 'Elasticsearch', 'SNMP', 'RDP', 'VNC', 'WinRM', 'MySQL', 'PostgreSQL', 'MSSQL', 'Oracle', 'NFS'):
            issues.append({
                'type': 'open_service',
                'summary': f"Open {port['service']} service on port {port['port']}",
                'details': 'High-risk, legacy, administrative, database, or infrastructure service is exposed and should be restricted, hardened, or disabled if unnecessary.',
                'severity': 'high' if port['service'] in ('Telnet', 'SMB', 'Docker', 'Redis', 'MongoDB', 'Memcached', 'Elasticsearch', 'RDP', 'VNC', 'WinRM') else 'medium',
            })
    http = web_results.get('http')
    https = web_results.get('https')
    paths = web_results.get('paths', [])
    tls = web_results.get('tls')
    analyze_web_response('http', http, issues)
    analyze_web_response('https', https, issues)
    analyze_http_methods(web_results.get('methods', {}), issues)
    if https and https['code'] == 200 and tls is None:
        issues.append({
            'type': 'https_issue',
            'summary': 'HTTPS is available but certificate details could not be retrieved.',
            'details': 'SSL/TLS configuration may be broken or using an unsupported protocol.',
            'severity': 'high',
        })
    if tls:
        subject_cn = tls['subject'].get('commonName') if tls.get('subject') else None
        if not subject_cn:
            issues.append({
                'type': 'cert_issue',
                'summary': 'TLS certificate missing a common name',
                'details': 'Certificate may be misconfigured for the target hostname.',
                'severity': 'medium',
            })
        analyze_tls_certificate(tls, issues)
    for path in paths:
        if path['code'] == 200:
            issues.append({
                'type': 'sensitive_path',
                'summary': f'Accessible sensitive path found: {path["path"]}',
                'details': 'This potentially exposes configuration, source code, logs, backups, or administrative entry points.',
                'severity': path_severity(path['path']),
            })
        elif path['code'] in (401, 403):
            issues.append({
                'type': 'protected_path',
                'summary': f'Protected or restricted path exists: {path["path"]}',
                'details': 'Authentication is required, which may indicate a hidden admin or login panel.',
                'severity': 'low',
            })
    return issues


def analyze_web_response(scheme, response, issues):
    if not response:
        return

    headers = response.get('headers', {})
    body = response.get('body', '')
    lower_body = body.lower()

    if scheme == 'http' and response.get('final_url', '').startswith('http://') and response.get('code') == 200:
        issues.append({
            'type': 'insecure_http',
            'summary': 'HTTP service is available without forcing HTTPS',
            'details': 'Plain HTTP can expose traffic to interception. Redirect HTTP traffic to HTTPS when possible.',
            'severity': 'medium',
        })

    if 'server' in headers:
        issues.append({
            'type': 'server_banner',
            'summary': f"HTTP server reveals banner: {headers['server']}",
            'details': 'Server header can leak software names or versions to attackers.',
            'severity': 'info',
        })

    if 'x-powered-by' in headers:
        issues.append({
            'type': 'technology_disclosure',
            'summary': f"Application technology disclosed: {headers['x-powered-by']}",
            'details': 'Technology disclosure can help attackers choose version-specific payloads.',
            'severity': 'info',
        })

    check_security_headers(scheme, headers, issues)
    check_cookie_flags(scheme, response.get('cookies', []), issues)
    check_cors(headers, issues)

    if re.search(r'<title>\s*index of\s*/?', lower_body) or 'directory listing for /' in lower_body:
        issues.append({
            'type': 'directory_listing',
            'summary': 'Directory listing appears to be enabled',
            'details': 'Directory indexes can expose files, source code, backups, and internal structure.',
            'severity': 'high',
        })

    default_markers = [
        'apache2 ubuntu default page',
        'apache http server test page',
        'welcome to nginx',
        'iis windows server',
        'test page for the nginx http server',
        'it works!',
    ]
    if any(marker in lower_body for marker in default_markers):
        issues.append({
            'type': 'default_page',
            'summary': 'Default web server page detected',
            'details': 'Default pages often indicate unfinished hardening or a forgotten virtual host.',
            'severity': 'low',
        })

    error_markers = [
        'traceback (most recent call last)',
        'warning: mysql',
        'fatal error',
        'stack trace',
        'sql syntax',
    ]
    if any(marker in lower_body for marker in error_markers):
        issues.append({
            'type': 'verbose_error',
            'summary': 'Verbose application error content detected',
            'details': 'Detailed errors can expose file paths, database behavior, framework internals, or query structure.',
            'severity': 'medium',
        })


def check_security_headers(scheme, headers, issues):
    csp = headers.get('content-security-policy', '')
    required_headers = {
        'x-content-type-options': ('medium', 'Prevents browsers from MIME-sniffing unsafe content.'),
        'referrer-policy': ('low', 'Limits sensitive URL data leaked through the Referer header.'),
        'permissions-policy': ('low', 'Restricts browser features such as camera, microphone, and geolocation.'),
    }
    for header, (severity, details) in required_headers.items():
        if header not in headers:
            issues.append({
                'type': 'missing_security_header',
                'summary': f'Missing security header: {header}',
                'details': details,
                'severity': severity,
            })

    if 'x-frame-options' not in headers and 'frame-ancestors' not in csp.lower():
        issues.append({
            'type': 'missing_security_header',
            'summary': 'Missing clickjacking protection',
            'details': 'Set X-Frame-Options or a CSP frame-ancestors directive to reduce clickjacking risk.',
            'severity': 'medium',
        })

    if not csp:
        issues.append({
            'type': 'missing_security_header',
            'summary': 'Missing security header: content-security-policy',
            'details': 'A Content Security Policy helps reduce XSS and content injection impact.',
            'severity': 'medium',
        })
    elif "'unsafe-inline'" in csp.lower() or "'unsafe-eval'" in csp.lower():
        issues.append({
            'type': 'weak_csp',
            'summary': 'Content Security Policy allows unsafe script behavior',
            'details': 'unsafe-inline or unsafe-eval weakens CSP protection against script injection.',
            'severity': 'medium',
        })

    if scheme == 'https' and 'strict-transport-security' not in headers:
        issues.append({
            'type': 'missing_security_header',
            'summary': 'Missing security header: strict-transport-security',
            'details': 'HSTS tells browsers to keep using HTTPS and reduces downgrade attack exposure.',
            'severity': 'high',
        })


def check_cookie_flags(scheme, cookies, issues):
    for cookie in cookies:
        cookie_name = cookie.split('=', 1)[0].strip() or 'unnamed'
        lower_cookie = cookie.lower()
        if 'httponly' not in lower_cookie:
            issues.append({
                'type': 'cookie_misconfiguration',
                'summary': f'Cookie missing HttpOnly flag: {cookie_name}',
                'details': 'HttpOnly helps protect cookies from client-side script access after XSS.',
                'severity': 'medium',
            })
        if scheme == 'https' and 'secure' not in lower_cookie:
            issues.append({
                'type': 'cookie_misconfiguration',
                'summary': f'Cookie missing Secure flag: {cookie_name}',
                'details': 'Secure limits cookie transmission to HTTPS connections.',
                'severity': 'medium',
            })
        if 'samesite' not in lower_cookie:
            issues.append({
                'type': 'cookie_misconfiguration',
                'summary': f'Cookie missing SameSite attribute: {cookie_name}',
                'details': 'SameSite helps reduce cross-site request forgery exposure.',
                'severity': 'low',
            })


def check_cors(headers, issues):
    allow_origin = headers.get('access-control-allow-origin', '').strip()
    allow_credentials = headers.get('access-control-allow-credentials', '').strip().lower()
    if allow_origin == '*':
        issues.append({
            'type': 'cors_misconfiguration',
            'summary': 'CORS allows any origin',
            'details': 'Wildcard CORS should be avoided for sensitive applications and APIs.',
            'severity': 'high' if allow_credentials == 'true' else 'medium',
        })


def analyze_http_methods(methods_by_scheme, issues):
    risky_methods = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'}
    for scheme, methods in methods_by_scheme.items():
        exposed = sorted(risky_methods.intersection(set(methods)))
        if exposed:
            issues.append({
                'type': 'dangerous_http_methods',
                'summary': f'{scheme.upper()} allows risky methods: {", ".join(exposed)}',
                'details': 'Restrict HTTP methods to only those required by the application.',
                'severity': 'high' if {'PUT', 'DELETE', 'TRACE'}.intersection(exposed) else 'medium',
            })


def analyze_tls_certificate(tls, issues):
    subject = tls.get('subject') or {}
    issuer = tls.get('issuer') or {}
    if subject and issuer and subject == issuer:
        issues.append({
            'type': 'cert_issue',
            'summary': 'TLS certificate appears to be self-signed',
            'details': 'Self-signed certificates are not trusted by default and should be replaced for public services.',
            'severity': 'medium',
        })

    not_after = tls.get('notAfter')
    expires_at = parse_tls_date(not_after)
    if not expires_at:
        return
    now = datetime.datetime.now(datetime.timezone.utc)
    days_left = (expires_at - now).days
    if days_left < 0:
        issues.append({
            'type': 'cert_issue',
            'summary': 'TLS certificate is expired',
            'details': f'Certificate expired on {not_after}.',
            'severity': 'critical',
        })
    elif days_left <= 30:
        issues.append({
            'type': 'cert_issue',
            'summary': 'TLS certificate expires soon',
            'details': f'Certificate expires on {not_after} ({days_left} days remaining).',
            'severity': 'medium',
        })


def parse_tls_date(value):
    if not value:
        return None
    try:
        parsed = datetime.datetime.strptime(value, '%b %d %H:%M:%S %Y %Z')
        return parsed.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def path_severity(path):
    critical_markers = (
        '.git', '.env', 'id_rsa', 'backup', '.sql', '.tar.gz', '.zip',
        'dump', 'wp-config', 'config.php',
    )
    if any(marker in path.lower() for marker in critical_markers):
        return 'critical'
    return 'medium'


def build_report(target, ip, geo, ports, web_results, subdomains, issues):
    lines = []
    lines.append(f'{Colors.BOLD}{Colors.MAGENTA}VulnRaider Scan Report{Colors.END}')
    lines.append(f'{Colors.MAGENTA}{"=" * 58}{Colors.END}')
    lines.append(f'{Colors.CYAN}Target:{Colors.END} {target}')
    lines.append(f'{Colors.CYAN}IP Address:{Colors.END} {ip}')
    lines.append(f'{Colors.CYAN}Scan Time:{Colors.END} {datetime.datetime.now(datetime.timezone.utc).isoformat()} UTC')
    if geo:
        location = ', '.join(item for item in [geo.get('city'), geo.get('region'), geo.get('country')] if item)
        lines.append(f'{Colors.CYAN}Location:{Colors.END} {location or "unknown"}')
        if geo.get('isp'):
            lines.append(f'{Colors.CYAN}ISP:{Colors.END} {geo["isp"]}')
    lines.append('')
    
    lines.append(f'{Colors.YELLOW}{Colors.BOLD}[ OPEN PORTS ]{Colors.END}')
    if ports:
        lines.append(f'{"Port":<8} {"Service":<12} Version')
        lines.append(f'{"-" * 8} {"-" * 12} {"-" * 32}')
        for p in ports:
            lines.append(f'{Colors.GREEN}{p["port"]:<8}{Colors.END} {p["service"]:<12} {p.get("version", "unknown")}')
    else:
        lines.append('No open ports detected in the selected port list.')
    lines.append('')
    
    if web_results.get('http') or web_results.get('https'):
        lines.append(f'{Colors.YELLOW}{Colors.BOLD}[ WEB SERVICES ]{Colors.END}')
        lines.append(f'{"Scheme":<8} {"Status":<8} Server')
        lines.append(f'{"-" * 8} {"-" * 8} {"-" * 32}')
        for scheme in ['http', 'https']:
            value = web_results.get(scheme)
            if value:
                status_color = Colors.GREEN if value['code'] == 200 else Colors.YELLOW
                server = value['headers'].get('server')
                lines.append(f'{status_color}{scheme.upper():<8}{Colors.END} {value["code"]:<8} {server or "unknown"}')
        lines.append('')
    
    if web_results.get('paths'):
        lines.append(f'{Colors.YELLOW}{Colors.BOLD}[ INTERESTING PATHS ]{Colors.END}')
        lines.append(f'{"Path":<24} Status')
        lines.append(f'{"-" * 24} {"-" * 8}')
        for path in web_results['paths']:
            lines.append(f'{Colors.GREEN}{path["path"]:<24}{Colors.END} {path.get("scheme", "http").upper()} {path["code"]}')
        lines.append('')
    
    if web_results.get('tls'):
        tls = web_results['tls']
        lines.append(f'{Colors.YELLOW}{Colors.BOLD}[ SSL/TLS CERTIFICATE ]{Colors.END}')
        lines.append(f'{Colors.CYAN}    Domain:{Colors.END} {tls["subject"].get("commonName", "N/A")}')
        lines.append(f'{Colors.CYAN}    Issuer:{Colors.END} {tls["issuer"].get("commonName", "N/A")}')
        lines.append(f'{Colors.CYAN}    Valid Until:{Colors.END} {tls.get("notAfter", "N/A")}')
        lines.append('')

    lines.append(f'{Colors.YELLOW}{Colors.BOLD}[ SUBDOMAINS ]{Colors.END}')
    if subdomains:
        lines.append(f'{"Host":<32} IP Address')
        lines.append(f'{"-" * 32} {"-" * 32}')
        for item in subdomains:
            lines.append(f'{Colors.GREEN}{item["host"]:<32}{Colors.END} {", ".join(item["ips"])}')
    else:
        lines.append('No subdomains discovered with the built-in wordlist.')
    lines.append('')
    
    if issues:
        lines.append(f'{Colors.RED}{Colors.BOLD}[ VULNERABILITIES ]{Colors.END}')
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        severity_colors = {
            'critical': Colors.RED + Colors.BOLD,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.BLUE,
            'info': Colors.CYAN,
        }
        for severity in severity_order:
            grouped = [item for item in issues if item['severity'] == severity]
            for item in grouped:
                color = severity_colors.get(severity, Colors.WHITE)
                lines.append(f'{color}{severity.upper():<9}{Colors.END} {item["type"]}')
                lines.append(f'  Vulnerability: {item["summary"]}')
                lines.append(f'  Details: {item["details"]}')
        lines.append('')
    else:
        lines.append(f'{Colors.GREEN}{Colors.BOLD}[ VULNERABILITIES ]{Colors.END}')
        lines.append('No vulnerabilities detected by the enabled checks.')
        lines.append('')
    return '\n'.join(lines)


def save_text_report(report_text, filename):
    with open(filename, 'w', encoding='utf-8') as outfile:
        outfile.write(strip_colors(report_text))


def save_json_report(data, filename):
    with open(filename, 'w', encoding='utf-8') as outfile:
        json.dump(data, outfile, indent=2)


def main():
    global VERBOSE
    print_logo()
    args = parse_args()
    VERBOSE = args.verbose
    hostname = normalize_target(args.target)
    web_host = normalize_web_target(args.target, hostname)
    if not hostname:
        print(f'{Colors.RED}Invalid target. Provide a valid IP, hostname, or URL.{Colors.END}')
        sys.exit(1)

    debug(f'Resolving target: {hostname}')
    ip = resolve_target(hostname)
    if not ip:
        print(f'{Colors.RED}Unable to resolve target: {hostname}{Colors.END}')
        sys.exit(1)

    print(f'{Colors.BLUE}Scanning {hostname} ({ip})...{Colors.END}\n')
    
    geo = geo_lookup(ip) if args.geo else None
    ports = []
    if not args.web_only:
        port_list = []
        for port_text in args.ports.split(','):
            if port_text.strip().isdigit():
                port_list.append(int(port_text.strip()))
        ports = scan_ports(ip, hostname, port_list, args.timeout)
    web_results = scan_web(web_host, args.timeout, args.no_ssl, hostname)
    subdomains = discover_subdomains(hostname)
    issues = assess_vulnerabilities(args.target, ip, geo, ports, web_results)

    report_text = build_report(args.target, ip, geo, ports, web_results, subdomains, issues)
    
    # Print report to terminal
    print(report_text)
    
    if args.output:
        save_text_report(report_text, args.output)
        print(f'{Colors.GREEN}Report saved to: {args.output}{Colors.END}')
    if args.json_output:
        json_data = {
            'target': args.target,
            'hostname': hostname,
            'ip': ip,
            'geolocation': geo,
            'ports': ports,
            'web': web_results,
            'subdomains': subdomains,
            'findings': issues,
        }
        save_json_report(json_data, args.json_output)
        print(f'{Colors.GREEN}JSON output saved to: {args.json_output}{Colors.END}')


if __name__ == '__main__':
    main()
