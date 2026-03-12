# ============================================================================
# internet_routes.py - Internet Mode Module
# ============================================================================
# Handles: Automatic request logging middleware, honey bait routes,
#          catch-all 404 for directory enumeration, rate limiting,
#          and admin page protection.
# ============================================================================
# Phase 1: before_request middleware (auto-logs all attacker traffic)
# Phase 2: Honey routes (/robots.txt, /.env, /config.bin, etc.)
# Phase 3: Catch-all route (captures Gobuster / dirb probes)
# Phase 4: Rate limiting (stealth — returns 404, not 429)
# Phase 5: Admin protection (session-based, Internet Mode only)
# ============================================================================

from flask import Blueprint, request, Response, redirect, session
import sqlite3
import json
import time
import os
import random
from datetime import datetime

internet_bp = Blueprint('internet', __name__)

# ============================================================================
# MODULE STATE (initialized by init_internet_module from app.py)
# ============================================================================
_app_config = {}
_current_persona = {}
_log_to_db = None            # shared function from app.py
_get_reputation_score = None  # shared function from app.py
_send_alert = None           # shared function from notifier.py (FR-10)

# Rate limiting store: { ip_string: [timestamp_float, ...] }
_rate_limit_store = {}


def init_internet_module(app_config, current_persona, log_to_db_func, get_reputation_func, send_alert_func=None):
    """Called once from app.py to inject shared state and functions."""
    global _app_config, _current_persona, _log_to_db, _get_reputation_score, _send_alert
    _app_config = app_config
    _current_persona = current_persona
    _log_to_db = log_to_db_func
    _get_reputation_score = get_reputation_func
    _send_alert = send_alert_func


def reset_rate_limits():
    """Clear the rate limit store. Called when settings change."""
    global _rate_limit_store
    _rate_limit_store = {}


# ============================================================================
# ADMIN PATH WHITELIST
# ============================================================================
# These are YOUR management pages — protected in Internet Mode.
# The middleware ensures attackers get 404 for these paths.
# ============================================================================
ADMIN_PREFIXES = (
    '/dashboard',
    '/campaigns',
    '/logs',
    '/simulation',
    '/forensic',
    '/scripting',
    '/settings',
    '/mitre',
    '/api/',
    '/static/',
    '/lab/',
    '/admin/set_persona',
)


# ============================================================================
# VENDOR 404 HELPER (reused across middleware, catch-all, error handlers)
# ============================================================================
def _vendor_404_response():
    """Return a vendor-styled 404 page that looks like a real IoT device."""
    vendor = _current_persona.get('vendor', 'Generic')
    name = _current_persona.get('name', 'IoT Router')
    html = f"""<!DOCTYPE html>
<html>
<head><title>{name} - Error</title>
<style>
body {{ font-family: Arial, sans-serif; background: #f4f4f4; display: flex;
       justify-content: center; align-items: center; height: 100vh; margin: 0; }}
.error-box {{ background: white; padding: 40px; border-radius: 8px;
             box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; max-width: 400px; }}
h1 {{ color: #c0392b; font-size: 48px; margin: 0; }}
p {{ color: #666; font-size: 14px; }}
a {{ color: #2980b9; text-decoration: none; }}
.footer {{ margin-top: 20px; font-size: 11px; color: #999; }}
</style>
</head>
<body>
<div class="error-box">
<h1>404</h1>
<p>The requested page was not found on this device.</p>
<p><a href="/">Return to login</a></p>
<div class="footer">&copy; 2025 {vendor} Networks</div>
</div>
</body>
</html>"""
    return Response(html, status=404, mimetype='text/html')


# ============================================================================
# ADMIN AUTHENTICATION (Internet Mode only)
# ============================================================================
# Student visits /honeypot-admin → browser shows native login popup.
# Correct credentials → session cookie set → all admin pages work.
# Attacker probing /dashboard, /logs etc → sees vendor 404.
# ============================================================================

def _check_admin_auth():
    """Check Basic Auth credentials against config."""
    auth = request.authorization
    if not auth:
        return False
    expected_user = _app_config.get('admin_username', 'admin')
    expected_pass = _app_config.get('admin_password', 'fyp2026')
    return auth.username == expected_user and auth.password == expected_pass


@internet_bp.route('/honeypot-admin')
def admin_login():
    """Admin entry point — shows browser login prompt."""
    # Already authenticated via session? Go to dashboard.
    if session.get('hp_admin'):
        return redirect('/dashboard')
    
    # Check Basic Auth credentials
    if _check_admin_auth():
        session['hp_admin'] = True
        return redirect('/dashboard')
    
    # No credentials or wrong credentials → prompt browser login dialog
    vendor = _current_persona.get('vendor', 'Generic')
    return Response(
        'Authentication required.\n',
        401,
        {'WWW-Authenticate': f'Basic realm="{vendor} Administration"'}
    )


@internet_bp.route('/honeypot-admin/logout')
def admin_logout():
    """Revoke admin session."""
    session.pop('hp_admin', None)
    return redirect('/')


# ============================================================================
# PHASE 1 — MIDDLEWARE (the core engine)
# ============================================================================
# Fires BEFORE every request. Handles:
#   - Admin protection (session check in Internet Mode)
#   - Automatic attack logging
#   - Stealth rate limiting
# ============================================================================
@internet_bp.before_app_request
def internet_mode_logger():
    """Runs before EVERY request in ALL modes.
    - Admin auth: always enforced (both Simulation and Internet)
    - Attack logging: only in Internet Mode
    """

    path = request.path

    # ── 1. Admin auth endpoint itself — always accessible, never logged ──
    if path.startswith('/honeypot-admin'):
        return None

    # ── 2. Static files — always serve without auth ──
    if path.startswith('/static/'):
        return None

    # ── 3. Admin paths — ALWAYS require session authentication ──
    if any(path.startswith(prefix) for prefix in ADMIN_PREFIXES):
        if session.get('hp_admin'):
            return None          # Authenticated → serve page normally
        else:
            if _app_config.get('mode') == 'internet':
                return _vendor_404_response()  # Internet: attacker sees 404
            else:
                return redirect('/honeypot-admin')  # Simulation: redirect to login

    # ── 4. Attack logging — only in Internet Mode ──
    if _app_config.get('mode') != 'internet':
        return None

    # ── Everything below is attacker-facing honeypot surface ──
    ip = request.remote_addr

    # Rate limit check (stealth: returns 404, not 429)
    if not _check_rate_limit(ip):
        _log_request(request, rate_limited=True)
        return _vendor_404_response()   # Attacker sees normal 404

    # Log the request (middleware handles ALL logging now)
    _log_request(request)

    # Return None = let Flask continue to the matched route handler
    return None


# ============================================================================
# INTERNAL HELPERS
# ============================================================================
def _log_request(req, rate_limited=False):
    """Extract full request data and log to database."""
    ip = req.remote_addr
    method = req.method
    path = req.path
    user_agent = req.headers.get('User-Agent', 'Unknown')

    # ── Build payload dict from all input sources ──
    payload = {}

    # Query string parameters (GET params)
    if req.args:
        payload['query_params'] = req.args.to_dict()

    # Form data (POST body)
    if method == 'POST':
        form_data = req.form.to_dict()
        if form_data:
            payload['form_data'] = form_data

        # Raw body (for non-form POST like JSON or binary)
        if not form_data:
            try:
                raw = req.get_data(as_text=True)
                if raw:
                    payload['raw_body'] = raw[:2000]  # Cap at 2KB for safety
            except Exception:
                pass

    # Include selected headers that reveal attacker tools
    interesting_headers = {}
    for h in ['User-Agent', 'Referer', 'Origin', 'X-Forwarded-For',
              'Content-Type', 'Accept', 'Authorization', 'Cookie']:
        val = req.headers.get(h)
        if val:
            interesting_headers[h] = val
    if interesting_headers:
        payload['headers'] = interesting_headers

    if rate_limited:
        payload['rate_limited'] = True

    # ── Classify the attack ──
    attack_type = _classify_attack(req, payload)

    # ── Get IP reputation (with caching) ──
    score, country = _get_reputation_score(ip)

    # ── Write to database ──
    vendor = _current_persona.get('vendor', 'Generic')
    _log_to_db(
        ip, method, path,
        json.dumps(payload) if payload else '{}',
        user_agent, score, attack_type, country, vendor,
        source='internet'
    )

    # ── Trigger real-time email alert for high-severity attacks (FR-10) ──
    if _send_alert and not rate_limited:
        _send_alert({
            'ip': ip,
            'method': method,
            'path': path,
            'attack_type': attack_type,
            'abuse_score': score,
            'country': country,
            'user_agent': user_agent,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'payload': json.dumps(payload)[:500] if payload else '{}'
        })


def _classify_attack(req, payload_dict):
    """
    Enhanced attack classifier for real Internet Mode traffic.
    Uses path, method, payload, query string, and user-agent signals.
    Returns MITRE ATT&CK tagged category string.
    """
    path = req.path.lower()
    method = req.method
    user_agent = req.headers.get('User-Agent', '').lower()

    # Build a single searchable string from all inputs
    search_parts = [path]
    if payload_dict.get('form_data'):
        search_parts.append(str(payload_dict['form_data']).lower())
    if payload_dict.get('raw_body'):
        search_parts.append(str(payload_dict['raw_body']).lower())
    if payload_dict.get('query_params'):
        search_parts.append(str(payload_dict['query_params']).lower())
    full_input = ' '.join(search_parts)

    # ── 1. SQL Injection (T1190: Exploit Public-Facing Application) ──
    sqli_sigs = [
        "union select", "' or '", "' or 1=1", "or 1=1--", "drop table",
        "information_schema", "sleep(", "benchmark(", "load_file(",
        "into outfile", "' and '", "extractvalue(", "updatexml(",
        "group_concat(", "order by ", "having ", "1=1", "1' or",
    ]
    if any(sig in full_input for sig in sqli_sigs):
        return "SQL Injection (T1190)"

    # ── 2. Directory Traversal (T1083: File and Directory Discovery) ──
    # Checked BEFORE Command Injection because paths like ../../../../etc/passwd
    # contain "etc/passwd" which would false-positive on CmdI signatures.
    # Traversal = path escape via ../ sequences; CmdI = shell metacharacters.
    # Two-layer detection:
    #   Layer 1: ../ sequences (may be stripped by curl --path-as-is or Werkzeug)
    #   Layer 2: Sensitive file paths in the URL — if someone requests /etc/passwd
    #            directly in the path, it's traversal regardless of how ../ was handled.
    traversal_sigs = ["../", "..\\", "%2e%2e", "....//", "%252e"]
    if any(sig in full_input for sig in traversal_sigs):
        return "Directory Traversal (T1083)"
    
    # Sensitive file targets that should never appear in a URL path
    traversal_targets = [
        "etc/passwd", "etc/shadow", "etc/hosts", "etc/hostname",
        "proc/self", "proc/version", "proc/cpuinfo",
        "windows/system32", "windows/win.ini", "boot.ini",
        "var/log/", "tmp/", "root/.ssh", "root/.bash_history"
    ]
    if any(target in path for target in traversal_targets):
        return "Directory Traversal (T1083)"

    # ── 3. Command Injection (T1059: Command and Scripting Interpreter) ──
    # "etc/passwd" and "etc/shadow" removed — now caught by traversal targets.
    # Includes both "; cat " and ";cat " variants — real attackers often
    # skip the space between the shell metacharacter and the command.
    cmd_sigs = [
        "; cat ", ";cat ", "| cat ", "|cat ", "`cat ", "$(cat",
        "; ls", ";ls ", "| ls ", "|ls ",
        "; id", ";id", "| id", "|id",
        "; wget ", ";wget ", "; curl ", ";curl ",
        "| wget", "|wget", "| curl", "|curl",
        "/bin/sh", "/bin/bash",
        "; rm ", ";rm ", "| rm ", "|rm ",
        "; nc ", ";nc ", "| nc ", "|nc ",
        "; python", ";python", "| python", "|python",
        "; perl", ";perl", "| perl", "|perl",
        "; php", ";php", "| php", "|php",
        "; echo ", ";echo ", "| echo ", "|echo ",
        "${ifs}", "; uname", ";uname", "| uname", "|uname",
        "; whoami", ";whoami", "| whoami", "|whoami",
        "`id`", "`whoami`", "$(id)", "$(whoami)", "; ifconfig", ";ifconfig",
    ]
    if any(sig in full_input for sig in cmd_sigs):
        return "Command Injection (T1059)"

    # ── 4. XSS (T1059.007: JavaScript) ──
    xss_sigs = [
        "<script", "javascript:", "onerror=", "onload=", "alert(",
        "prompt(", "confirm(", "document.cookie", "document.location",
        "<img src=", "<svg ", "onfocus=", "onmouseover=",
    ]
    if any(sig in full_input for sig in xss_sigs):
        return "XSS (T1059.007)"

    # ── 5. Malicious File Upload (T1105: Ingress Tool Transfer) ──
    upload_sigs = [".php", ".jsp", ".asp", ".sh", ".py", "webshell",
                   "c99", "r57", "b374k", "<?php"]
    if method == 'POST' and any(sig in full_input for sig in upload_sigs):
        return "Malicious Upload (T1105)"

    # ── 6. Brute Force (T1110: Brute Force) ──
    login_paths = ['/', '/login', '/auth', '/signin', '/cgi-bin/login',
                   '/userLogin', '/admin/login', '/user/login']
    if method == 'POST' and any(path == lp or path.startswith(lp + '?') for lp in login_paths):
        return "Brute Force (T1110)"

    # ── 7. Directory Enumeration (T1083: File and Directory Discovery) ──
    enum_paths = [
        '/admin', '/wp-admin', '/wp-login', '/phpmyadmin', '/config',
        '/backup', '/.env', '/.git', '/cgi-bin', '/setup.cgi', '/hnap1',
        '/manager', '/console', '/debug', '/test', '/dev', '/old',
        '/wp-content', '/wp-includes', '/xmlrpc.php', '/api/v1',
        '/swagger', '/.htaccess', '/.htpasswd', '/server-status',
        '/solr', '/actuator', '/jenkins', '/shell', '/cmd',
        '/config.bin', '/backup.tar.gz', '/firmware', '/upgrade',
        # IP camera endpoints
        '/ISAPI', '/onvif', '/axis-cgi', '/snapshot.cgi',
        '/mjpg', '/video', '/livestream', '/doc/page',
    ]
    if any(path == ep or path.startswith(ep + '/') for ep in enum_paths):
        return "Directory Enumeration (T1083)"

    # ── 8. Known scanner user-agents ──
    scanner_agents = ['nmap', 'nikto', 'gobuster', 'dirbuster', 'sqlmap',
                      'hydra', 'masscan', 'zgrab', 'nuclei', 'wfuzz',
                      'ffuf', 'dirb', 'skipfish', 'arachni', 'burp',
                      'zap proxy', 'openvas', 'nessus', 'shodan', 'censys']
    if any(scanner in user_agent for scanner in scanner_agents):
        return "Reconnaissance (T1595)"

    # ── 9. Default: General Reconnaissance ──
    return "Reconnaissance (T1595)"


# ============================================================================
# PHASE 2 — HONEY ROUTES (bait files that real IoT devices often expose)
# ============================================================================
# These attract scanners and waste attacker time.
# Middleware already logs them — these just return convincing content.
# ============================================================================

@internet_bp.route('/robots.txt')
def honey_robots():
    """Attackers check robots.txt to find hidden directories."""
    content = """User-agent: *
Disallow: /admin
Disallow: /config
Disallow: /backup
Disallow: /cgi-bin/
Disallow: /logs
Disallow: /firmware
Disallow: /upgrade
Disallow: /debug
"""
    return Response(content, mimetype='text/plain')


@internet_bp.route('/sitemap.xml')
def honey_sitemap():
    """Fake sitemap listing enticing endpoints."""
    vendor = _current_persona.get('vendor', 'Generic')
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc><lastmod>2025-11-15</lastmod></url>
  <url><loc>/login</loc><lastmod>2025-11-15</lastmod></url>
  <url><loc>/admin</loc><lastmod>2025-10-20</lastmod></url>
  <url><loc>/status</loc><lastmod>2025-11-14</lastmod></url>
  <url><loc>/firmware</loc><lastmod>2025-09-03</lastmod></url>
</urlset>"""
    return Response(xml, mimetype='application/xml')


@internet_bp.route('/.env')
def honey_env():
    """Attackers scan for exposed .env files with credentials."""
    vendor = _current_persona.get('vendor', 'Generic')
    content = f"""# {vendor} Device Configuration
APP_ENV=production
APP_DEBUG=false
DB_HOST=127.0.0.1
DB_DATABASE=device_config
DB_USERNAME=admin
DB_PASSWORD=admin123
ADMIN_EMAIL=admin@router.local
SECRET_KEY=fw_{vendor.lower()}_2024_x7k9m2
API_KEY=sk-fake-{random.randint(100000,999999)}
FIRMWARE_VERSION=3.2.1
"""
    return Response(content, mimetype='text/plain')


@internet_bp.route('/config.bin')
@internet_bp.route('/backup.bin')
@internet_bp.route('/firmware.bin')
def honey_binary():
    """Return random bytes — attacker wastes time downloading fake firmware."""
    garbage = os.urandom(4096)  # 4KB of random data
    filename = request.path.lstrip('/')
    return Response(
        garbage,
        mimetype='application/octet-stream',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@internet_bp.route('/backup.tar.gz')
def honey_backup():
    """Fake backup archive."""
    garbage = os.urandom(8192)  # 8KB of random data
    return Response(
        garbage,
        mimetype='application/gzip',
        headers={'Content-Disposition': 'attachment; filename="backup.tar.gz"'}
    )


@internet_bp.route('/cgi-bin/')
@internet_bp.route('/cgi-bin/<path:subpath>')
def honey_cgi(subpath=''):
    """Common IoT CGI endpoints — attackers probe these for RCE."""
    vendor = _current_persona.get('vendor', 'Generic')
    return Response(
        f'<html><head><title>{vendor} - CGI</title></head>'
        f'<body><h1>403 Forbidden</h1>'
        f'<p>Access denied. Authentication required.</p>'
        f'<hr><address>{vendor} HTTPD</address></body></html>',
        status=403,
        mimetype='text/html'
    )


@internet_bp.route('/setup.cgi')
def honey_setup_cgi():
    """D-Link / Netgear style setup CGI."""
    vendor = _current_persona.get('vendor', 'Generic')
    return Response(
        f'<html><head><title>{vendor} Setup</title></head>'
        f'<body><h1>Device Setup</h1>'
        f'<p>Please <a href="/">log in</a> to configure this device.</p>'
        f'<hr><address>{vendor} HTTPD</address></body></html>',
        mimetype='text/html'
    )


@internet_bp.route('/HNAP1/')
@internet_bp.route('/HNAP1')
def honey_hnap():
    """D-Link Home Network Administration Protocol — heavily targeted."""
    xml = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetDeviceSettingsResponse>
      <GetDeviceSettingsResult>OK</GetDeviceSettingsResult>
      <Type>Gateway</Type>
      <DeviceName>IoT-Gateway</DeviceName>
      <FirmwareVersion>3.02</FirmwareVersion>
      <VendorName>Generic</VendorName>
      <ModelName>DGL-5500</ModelName>
      <ModelDescription>Wireless AC Gaming Router</ModelDescription>
    </GetDeviceSettingsResponse>
  </soap:Body>
</soap:Envelope>"""
    return Response(xml, mimetype='text/xml')


@internet_bp.route('/.git/config')
@internet_bp.route('/.git/HEAD')
def honey_git():
    """Attackers scan for exposed git repos."""
    if request.path.endswith('HEAD'):
        return Response('ref: refs/heads/main\n', mimetype='text/plain')
    return Response(
        '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n'
        '\tbare = false\n\tlogallrefupdates = true\n',
        mimetype='text/plain'
    )


@internet_bp.route('/admin')
@internet_bp.route('/admin/')
@internet_bp.route('/admin/login')
def honey_admin():
    """Redirect admin probes to the main login page."""
    vendor = _current_persona.get('vendor', 'Generic')
    name = _current_persona.get('name', 'IoT Router')
    return Response(
        f'<html><head><title>{name} - Admin</title>'
        f'<meta http-equiv="refresh" content="2;url=/"></head>'
        f'<body style="font-family:Arial;text-align:center;padding:60px">'
        f'<h2>Redirecting to login...</h2>'
        f'<p>Authentication required for admin access.</p>'
        f'<hr><small>{vendor} Networks</small></body></html>',
        mimetype='text/html'
    )


@internet_bp.route('/status')
@internet_bp.route('/device/status')
def honey_status():
    """Fake device status page — looks like a real IoT dashboard."""
    vendor = _current_persona.get('vendor', 'Generic')
    uptime_days = random.randint(12, 365)
    return Response(
        json.dumps({
            "device": vendor,
            "model": "WR-3200",
            "firmware": "3.2.1-build20250815",
            "uptime": f"{uptime_days}d {random.randint(0,23)}h {random.randint(0,59)}m",
            "wan_ip": f"203.0.113.{random.randint(1,254)}",
            "lan_ip": "192.168.1.1",
            "dns": ["8.8.8.8", "8.8.4.4"],
            "clients_connected": random.randint(3, 18),
            "cpu_usage": f"{random.randint(8,45)}%",
            "memory_usage": f"{random.randint(30,72)}%",
            "wifi_enabled": True,
            "firewall": "enabled"
        }, indent=2),
        mimetype='application/json'
    )


@internet_bp.route('/firmware')
@internet_bp.route('/firmware/')
@internet_bp.route('/upgrade')
def honey_firmware():
    """Fake firmware update page."""
    vendor = _current_persona.get('vendor', 'Generic')
    return Response(
        f'<html><head><title>{vendor} - Firmware</title></head>'
        f'<body style="font-family:Arial;padding:40px">'
        f'<h2>Firmware Update</h2>'
        f'<p>Current version: <b>3.2.1</b></p>'
        f'<p>Latest version: <b>3.2.3</b></p>'
        f'<p><a href="/">Login required</a> to perform update.</p>'
        f'<hr><small>&copy; 2025 {vendor} Networks</small></body></html>',
        mimetype='text/html'
    )


# ============================================================================
# IP CAMERA HONEY ROUTES (FR-3: second IoT device type)
# ============================================================================
# These endpoints mimic real IP camera APIs that attackers scan for.
# Active for all personas but especially realistic with camera vendors.
# ============================================================================

@internet_bp.route('/ISAPI/System/deviceInfo')
@internet_bp.route('/ISAPI/Security/users')
@internet_bp.route('/ISAPI/Streaming/channels')
def honey_isapi():
    """Hikvision ISAPI endpoints — most-scanned camera API globally."""
    vendor = _current_persona.get('vendor', 'Generic')
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema" version="2.0">\n'
        f'  <deviceName>{vendor} IP Camera</deviceName>\n'
        '  <deviceID>DS-2CD2142FWD-I20160801</deviceID>\n'
        '  <model>DS-2CD2142FWD-I</model>\n'
        '  <firmwareVersion>V5.4.5</firmwareVersion>\n'
        '  <macAddress>c0:56:e3:48:a1:f2</macAddress>\n'
        '</DeviceInfo>',
        mimetype='application/xml'
    )

@internet_bp.route('/onvif/device_service')
@internet_bp.route('/onvif/media_service')
def honey_onvif():
    """ONVIF protocol — universal IP camera discovery standard."""
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope">\n'
        '  <SOAP-ENV:Body>\n'
        '    <tds:GetDeviceInformationResponse>\n'
        '      <tds:Manufacturer>Generic</tds:Manufacturer>\n'
        '      <tds:Model>IPC-HDW2431T</tds:Model>\n'
        '      <tds:FirmwareVersion>2.800.0000</tds:FirmwareVersion>\n'
        '      <tds:HardwareId>1.0</tds:HardwareId>\n'
        '    </tds:GetDeviceInformationResponse>\n'
        '  </SOAP-ENV:Body>\n'
        '</SOAP-ENV:Envelope>',
        mimetype='application/xml'
    )

@internet_bp.route('/cgi-bin/snapshot.cgi')
@internet_bp.route('/snapshot.cgi')
@internet_bp.route('/mjpg/video.mjpg')
@internet_bp.route('/video/live')
@internet_bp.route('/livestream/0')
def honey_camera_stream():
    """Fake camera stream/snapshot endpoints — returns login redirect."""
    return Response(
        '<html><head><title>Authentication Required</title></head>'
        '<body style="font-family:Arial;background:#1a1a2e;color:#fff;'
        'display:flex;justify-content:center;align-items:center;height:100vh">'
        '<div style="text-align:center">'
        '<p style="font-size:48px">📹</p>'
        '<h2>Authentication Required</h2>'
        '<p style="color:#888">Please <a href="/" style="color:#e94560">login</a> to access the live view.</p>'
        '</div></body></html>',
        mimetype='text/html',
        status=401
    )

@internet_bp.route('/axis-cgi/param.cgi')
@internet_bp.route('/axis-cgi/mjpg/video.cgi')
def honey_axis_cgi():
    """Axis camera CGI endpoints."""
    return Response(
        'Error: Unauthorized\nLogin required to access camera parameters.\n',
        mimetype='text/plain',
        status=401
    )

@internet_bp.route('/doc/page/login.asp')
@internet_bp.route('/doc/page/config.asp')
def honey_hikvision_legacy():
    """Hikvision legacy web interface paths."""
    return redirect('/')


# ============================================================================
# PHASE 3 — CATCH-ALL ROUTE
# ============================================================================
# Captures ANY path not matched by explicit routes.
# This is where Gobuster / dirb / ffuf probes land.
# Returns a vendor-styled 404 so the attacker thinks it's a real device.
# ============================================================================

@internet_bp.route('/<path:undefined_path>')
def catch_all(undefined_path):
    """
    Catch directory enumeration and unknown path probes.
    Middleware already logged this request — just return a realistic 404.
    """
    if _app_config.get('mode') != 'internet':
        return Response('Not Found', status=404)

    return _vendor_404_response()


# ============================================================================
# PHASE 4 — RATE LIMITING (stealth — returns 404, not 429)
# ============================================================================
# A real IoT device wouldn't return 429. We return the same vendor-styled 404
# so Gobuster/Nmap can't distinguish rate-limited requests from real 404s.
# The rate_limited flag is stored in the payload for dashboard visibility.
# ============================================================================

def _check_rate_limit(ip):
    """
    Returns True if request is ALLOWED, False if RATE LIMITED.
    Uses a sliding window of 1 hour.
    """
    if not _app_config.get('rate_limit_enabled', True):
        return True  # Rate limiting disabled in settings

    max_per_hour = _app_config.get('max_requests_per_ip', 100)
    now = time.time()
    window = 3600  # 1 hour

    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = []

    # Prune timestamps older than the window
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if t > now - window]

    if len(_rate_limit_store[ip]) >= max_per_hour:
        return False

    _rate_limit_store[ip].append(now)
    return True