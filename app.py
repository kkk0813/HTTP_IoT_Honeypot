from flask import Flask, render_template, request, redirect, jsonify, url_for
from lab_routes import lab_bp, init_lab_module
from internet_routes import internet_bp, init_internet_module, reset_rate_limits
from notifier import init_notifier, send_alert, send_test_email, send_daily_summary
from werkzeug.middleware.proxy_fix import ProxyFix
import sqlite3, requests, threading, json, os, socket, random, secrets
from datetime import datetime
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)

# Trust Nginx reverse proxy headers so request.remote_addr shows real attacker IP.
# x_for=1 means trust one level of X-Forwarded-For (from Nginx).
# Without this, every log entry would show 127.0.0.1 instead of the attacker's IP.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Session config (cookie name looks like an IoT device, not Flask)
app.secret_key = secrets.token_hex(16)
app.config['SESSION_COOKIE_NAME'] = 'DEVICEID'
app.config['SESSION_COOKIE_HTTPONLY'] = True

CONFIG_FILE = 'honeypot_config.json'

# ============================================================================
# REALISM ENHANCEMENTS - Attack Sources with Geographic Distribution
# ============================================================================
ATTACK_SOURCES = [    
    # Known scanners/attackers (scores typically 50-100)
    {'ip': '185.220.101.1', 'country': 'DE', 'country_name': 'Germany', 'emoji': '🇩🇪', 'note': 'Tor Exit Node'},
    {'ip': '45.155.205.233', 'country': 'RU', 'country_name': 'Russia', 'emoji': '🇷🇺', 'note': 'Known Scanner'},
    {'ip': '193.32.162.159', 'country': 'RU', 'country_name': 'Russia', 'emoji': '🇷🇺', 'note': 'Brute Force'},
    {'ip': '218.92.0.107', 'country': 'CN', 'country_name': 'China', 'emoji': '🇨🇳', 'note': 'SSH Attacker'},
    {'ip': '222.186.180.130', 'country': 'CN', 'country_name': 'China', 'emoji': '🇨🇳', 'note': 'Port Scanner'},
    {'ip': '61.177.172.136', 'country': 'CN', 'country_name': 'China', 'emoji': '🇨🇳', 'note': 'Telnet Attacker'},
    {'ip': '103.152.118.120', 'country': 'ID', 'country_name': 'Indonesia', 'emoji': '🇮🇩', 'note': 'Botnet'},
    
    # Moderate risk (scores typically 20-60)
    {'ip': '167.94.138.126', 'country': 'US', 'country_name': 'USA', 'emoji': '🇺🇸', 'note': 'Censys Scanner'},
    {'ip': '71.6.199.23', 'country': 'US', 'country_name': 'USA', 'emoji': '🇺🇸', 'note': 'Research Scanner'},
    {'ip': '192.241.219.149', 'country': 'US', 'country_name': 'USA', 'emoji': '🇺🇸', 'note': 'DigitalOcean'},
    
    # Low risk / Research (scores typically 0-20)
    {'ip': '8.8.8.8', 'country': 'US', 'country_name': 'USA', 'emoji': '🇺🇸', 'note': 'Google DNS (Clean)'},
    {'ip': '1.1.1.1', 'country': 'AU', 'country_name': 'Australia', 'emoji': '🇦🇺', 'note': 'Cloudflare DNS (Clean)'},
]

# Background noise events (kept for future use: sample data generation, Internet mode)
NOISE_EVENTS = [
    {'path': '/favicon.ico', 'method': 'GET', 'payload': {}, 'type': 'Browser Request', 'agent': 'Mozilla/5.0 Chrome/120.0', 'score': 0},
    {'path': '/assets/css/style.css', 'method': 'GET', 'payload': {}, 'type': 'Browser Request', 'agent': 'Mozilla/5.0 Firefox/121.0', 'score': 0},
    {'path': '/', 'method': 'GET', 'payload': {}, 'type': 'Browser Request', 'agent': 'Mozilla/5.0 Edge/120.0', 'score': 0},
    {'path': '/robots.txt', 'method': 'GET', 'payload': {}, 'type': 'Search Crawler', 'agent': 'Googlebot/2.1', 'score': 0},
    {'path': '/', 'method': 'GET', 'payload': {}, 'type': 'Search Crawler', 'agent': 'Bingbot/2.0', 'score': 0},
    {'path': '/', 'method': 'GET', 'payload': {}, 'type': 'Security Scanner', 'agent': 'Shodan/1.0', 'score': 5},
    {'path': '/admin', 'method': 'GET', 'payload': {}, 'type': 'Security Scanner', 'agent': 'Nmap NSE', 'score': 8},
    {'path': '/health', 'method': 'GET', 'payload': {}, 'type': 'Health Check', 'agent': 'UptimeRobot/2.0', 'score': 0},
    {'path': '/setup.cgi', 'method': 'GET', 'payload': {}, 'type': 'IoT Misconfiguration', 'agent': 'curl/7.68.0', 'score': 10},
]

# HTTP Headers for device fingerprinting
VENDOR_HEADERS = {
    # Routers
    "TP-Link": "TP-LINK HTTPD/1.0",
    "D-Link": "lighttpd/1.4.28",
    "Cisco": "Cisco-HTTP/1.1",
    "Netgear": "NETGEAR HTTPd",
    "Linksys": "Linksys WRT HTTPD",
    "Ubiquiti": "UniFi/5.43.23",
    "Generic": "Apache/2.4.41 (Ubuntu)",
    # IP Cameras
    "Hikvision": "DNVRS-Webs",
    "Dahua": "Boa/0.94.14rc21",
    "Axis": "Apache/2.4.51 (Unix)",
}

# Map vendors to device types (FR-3: two IoT interfaces)
DEVICE_TYPES = {
    "Generic": "router", "Cisco": "router", "TP-Link": "router",
    "Netgear": "router", "D-Link": "router", "Linksys": "router",
    "Ubiquiti": "router",
    "Hikvision": "camera", "Dahua": "camera", "Axis": "camera",
}

# ============================================================================
# HTTP Header Spoofing - Makes honeypot fingerprint match vendor
# ============================================================================
@app.after_request
def apply_persona_headers(response):
    """Set persona Server header and clean up Flask fingerprints.
    Server header must be set HERE (not in WSGIRequestHandler) so it
    passes through Nginx reverse proxy to the attacker."""
    
    # Set vendor-specific Server header (e.g. "Cisco-HTTP/1.1")
    vendor = current_persona.get('vendor', 'Generic')
    response.headers["Server"] = VENDOR_HEADERS.get(vendor, 'GoAhead-Webs')
    
    # Security header
    response.headers["X-Frame-Options"] = "DENY"
    
    # Remove any headers that reveal Python/Flask
    response.headers.pop("X-Powered-By", None)
    
    return response

# ============================================================================
# CONFIGURATION
# ============================================================================
DEFAULT_CONFIG = {
    "mode": "simulation",
    "port": 5000,
    "rate_limit_enabled": True,
    "max_requests_per_ip": 100,
    "auto_block_threshold": 90,
    "api_key": "",
    "vendor": "Generic",
    "admin_username": "admin",
    "admin_password": "fyp2026",
    "lab_default_mode": "guided",
    "lab_default_attack": "brute_force",
    "lab_hint_delay": 8,
    "lab_edu_panel_open": True,
    # Email notification settings (FR-10)
    "email_alerts_enabled": False,
    "email_recipient": "",
    "email_smtp_address": "",
    "email_smtp_password": ""
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                loaded = json.load(f)
                # Merge with defaults to ensure new settings exist
                merged = DEFAULT_CONFIG.copy()
                merged.update(loaded)
                return merged
        except:
            return DEFAULT_CONFIG.copy()
    else:
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    
def get_bind_host(config):
    """Always bind to 0.0.0.0 — safe in host-only VM network.
    This means mode switching never requires a server restart."""
    return '0.0.0.0'

def save_config(config):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except:
        return False

honeypot_config = load_config()

# ============================================================================
# VENDOR / PERSONA HELPERS
# ============================================================================
VENDOR_DISPLAY_NAMES = {
    # Routers
    "Generic": "Generic IoT Router",
    "Cisco":   "Cisco IOS",
    "TP-Link": "TP-Link Deco",
    "Netgear": "Netgear Nighthawk",
    "D-Link":  "D-Link DIR",
    # IP Cameras
    "Hikvision": "Hikvision DS-2CD",
    "Dahua":     "Dahua DH-IPC",
    "Axis":      "Axis M3065-V",
}

def get_api_key():
    """Read API key from config (never hardcoded)."""
    return honeypot_config.get('api_key', '')

# Initialise persona from persisted config so it survives restarts
current_persona = {
    "vendor": honeypot_config.get("vendor", "Generic"),
    "name":   VENDOR_DISPLAY_NAMES.get(honeypot_config.get("vendor", "Generic"), "Generic IoT Router")
}

@app.route('/admin/set_persona', methods=['POST'])
def set_persona():
    """Legacy endpoint kept for compatibility; Settings page uses /api/config now."""
    global current_persona, honeypot_config
    vendor = request.json.get('vendor', 'Generic')
    current_persona["vendor"] = vendor
    current_persona["name"]   = VENDOR_DISPLAY_NAMES.get(vendor, vendor)
    honeypot_config["vendor"] = vendor
    save_config(honeypot_config)
    return jsonify({"status": "success", "active": current_persona})

# ============================================================================
# DATABASE
# ============================================================================
def init_db():
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            attack_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            source_ip TEXT,
            http_method TEXT,
            url_path TEXT,
            payload TEXT,
            user_agent TEXT,
            abuse_score INTEGER,
            attack_type TEXT,
            country_code TEXT,
            manufacturer TEXT,
            source TEXT DEFAULT 'simulation'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_intelligence (
            ip_address TEXT PRIMARY KEY,
            abuse_score INTEGER,
            country_code TEXT,
            last_updated DATETIME
        )
    ''')
    # Migration: add 'source' column to existing databases that lack it
    try:
        cursor.execute("SELECT source FROM attacks LIMIT 1")
    except sqlite3.OperationalError:
        cursor.execute("ALTER TABLE attacks ADD COLUMN source TEXT DEFAULT 'simulation'")
    conn.commit()
    conn.close()

def log_to_db(ip, method, path, payload, user_agent, score, category, country, manufacturer, source='internet'):
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO attacks (timestamp, source_ip, http_method, url_path, payload, user_agent, abuse_score, attack_type, country_code, manufacturer, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), ip, method, path, str(payload), user_agent, score, category, country, manufacturer, source))
    conn.commit()
    conn.close()

def log_interaction(req):
    """LEGACY: Previously called manually in each route.
    Now superseded by internet_routes.py middleware (before_request).
    Kept for backward compatibility — not actively called."""
    ip = req.remote_addr
    score, country = get_reputation_score(ip)
    payload = req.form.to_dict()
    if req.method == 'POST':
        category = classify_attack(payload)
    else:
        category = "Reconnaissance (T1595)"
    
    user_agent = req.headers.get('User-Agent', 'Unknown')
    log_to_db(ip, req.method, req.path, payload, user_agent, score, category, country, current_persona["vendor"], source='internet')

def get_reputation_score(ip):
    """Get IP reputation from AbuseIPDB (with caching)"""
    if ip.startswith('192.168.') or ip.startswith('10.') or ip == '127.0.0.1':
        return 0, 'Local'

    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute("SELECT abuse_score, country_code FROM ip_intelligence WHERE ip_address = ?", (ip,))
    cached_result = cursor.fetchone()
    
    if cached_result:
        conn.close()
        return cached_result[0], cached_result[1]

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': get_api_key()}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        score = data['data']['abuseConfidenceScore']
        country = data['data'].get('countryCode', 'Unknown')
        
        cursor.execute('INSERT INTO ip_intelligence VALUES (?, ?, ?, ?)', 
                      (ip, score, country, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return score, country
    except:
        if conn: conn.close()
        return 0, 'Unknown'
    
def classify_attack(payload_dict):
    """Simple attack classifier for real honeypot traffic (Internet Mode)"""
    payload_str = str(payload_dict).lower()
    sqli_signatures = ["' or '1'='1", "--", "union select", "drop table"]
    if any(sig in payload_str for sig in sqli_signatures):
        return "SQL Injection (T1190)"
    return "Brute Force (T1110)"

# ============================================================================
# ERROR HANDLERS — hide Flask error pages in Internet Mode
# ============================================================================
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(500)
def handle_http_error(e):
    """Return vendor-styled error pages in Internet Mode."""
    if honeypot_config.get('mode') == 'internet':
        vendor = current_persona.get('vendor', 'Generic')
        name = current_persona.get('name', 'IoT Router')
        code = getattr(e, 'code', 500)
        return (
            f'<html><head><title>{name} - Error</title>'
            f'<style>body{{font-family:Arial;background:#f4f4f4;display:flex;'
            f'justify-content:center;align-items:center;height:100vh;margin:0}}'
            f'.box{{background:white;padding:40px;border-radius:8px;'
            f'box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center;max-width:400px}}'
            f'h1{{color:#c0392b;font-size:48px;margin:0}}p{{color:#666;font-size:14px}}'
            f'a{{color:#2980b9;text-decoration:none}}'
            f'.f{{margin-top:20px;font-size:11px;color:#999}}</style></head>'
            f'<body><div class="box"><h1>{code}</h1>'
            f'<p>An error occurred on this device.</p>'
            f'<p><a href="/">Return to login</a></p>'
            f'<div class="f">&copy; 2025 {vendor} Networks</div>'
            f'</div></body></html>',
            code
        )
    # Simulation Mode — use Flask default error pages
    return e

# ============================================================================
# PAGE ROUTES
# ============================================================================
@app.route('/')
def home():
    # Middleware (internet_routes.py) handles logging in Internet Mode.
    vendor = current_persona["vendor"]
    device_type = DEVICE_TYPES.get(vendor, "router")
    template = 'camera_login.html' if device_type == 'camera' else 'login.html'
    return render_template(template, 
                           persona_name=current_persona["name"], 
                           vendor=current_persona["vendor"])

@app.route('/login', methods=['POST'])
def login():
    # Middleware already logged this POST request.
    import time
    time.sleep(0.5) 
    return redirect(url_for('home', error=1))

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', active_page='dashboard')

@app.route('/logs')
def logs_page():
    return render_template('logs.html', active_page='logs')

@app.route('/simulation')
def simulation_page():
    return render_template('simulation.html', active_page='simulation')

@app.route('/mitre')
def mitre_page():
    return render_template('mitre.html', active_page='mitre')

@app.route('/settings')
def settings_page():
    return render_template('settings.html', active_page='settings')

# ============================================================================
# API ENDPOINTS
# ============================================================================
@app.route('/api/config', methods=['GET', 'POST'])
def manage_config():
    global honeypot_config, current_persona
    
    if request.method == 'POST':
        data = request.json
        
        # --- Core settings ---
        if 'mode' in data:
            honeypot_config['mode'] = data['mode']
        
        if 'port' in data:
            honeypot_config['port'] = int(data['port'])
        
        if 'rate_limit_enabled' in data:
            honeypot_config['rate_limit_enabled'] = data['rate_limit_enabled']
        
        if 'max_requests_per_ip' in data:
            honeypot_config['max_requests_per_ip'] = int(data['max_requests_per_ip'])
        
        if 'auto_block_threshold' in data:
            honeypot_config['auto_block_threshold'] = int(data['auto_block_threshold'])

        # --- Device persona ---
        if 'vendor' in data:
            vendor = data['vendor']
            honeypot_config['vendor'] = vendor
            current_persona['vendor'] = vendor
            current_persona['name']   = VENDOR_DISPLAY_NAMES.get(vendor, vendor)

        # --- AbuseIPDB API key ---
        if 'api_key' in data:
            honeypot_config['api_key'] = data['api_key'].strip()

        # --- Lab settings ---
        if 'lab_default_mode' in data:
            honeypot_config['lab_default_mode'] = data['lab_default_mode']

        if 'lab_default_attack' in data:
            honeypot_config['lab_default_attack'] = data['lab_default_attack']

        if 'lab_hint_delay' in data:
            # Handle both string and int, allow 0 as valid value
            delay = data['lab_hint_delay']
            honeypot_config['lab_hint_delay'] = int(delay) if delay is not None else 8

        if 'lab_edu_panel_open' in data:
            honeypot_config['lab_edu_panel_open'] = data['lab_edu_panel_open']

        # --- Email notification settings (FR-10) ---
        if 'email_alerts_enabled' in data:
            honeypot_config['email_alerts_enabled'] = data['email_alerts_enabled']

        if 'email_recipient' in data:
            honeypot_config['email_recipient'] = data['email_recipient'].strip()

        if 'email_smtp_address' in data:
            honeypot_config['email_smtp_address'] = data['email_smtp_address'].strip()

        if 'email_smtp_password' in data:
            # Only update password if a non-empty value is sent
            # (frontend sends empty string when user hasn't changed it)
            pwd = data['email_smtp_password'].strip()
            if pwd:
                honeypot_config['email_smtp_password'] = pwd
        
        # Save config
        if save_config(honeypot_config):
            # Reset rate limits so new settings take effect immediately
            reset_rate_limits()
            
            calculated_bind_host = get_bind_host(honeypot_config)
            safe_config = {k: v for k, v in honeypot_config.items() if k not in ('api_key', 'email_smtp_password')}
            safe_config['bind_host'] = calculated_bind_host
            safe_config['api_key_set'] = bool(honeypot_config.get('api_key', ''))
            safe_config['email_smtp_password_set'] = bool(honeypot_config.get('email_smtp_password', ''))
            
            return jsonify({
                "status": "success",
                "message": "Configuration saved",
                "config": safe_config
            })
        else:
            return jsonify({"status": "error", "message": "Failed to save"}), 500
    
    # GET request
    config_out = dict(honeypot_config)
    config_out['bind_host'] = get_bind_host(honeypot_config)
    config_out['api_key_set'] = bool(honeypot_config.get('api_key', ''))
    config_out['device_type'] = DEVICE_TYPES.get(honeypot_config.get('vendor', 'Generic'), 'router')
    # Hide sensitive email password from GET response (just indicate if set)
    config_out['email_smtp_password_set'] = bool(honeypot_config.get('email_smtp_password', ''))
    config_out.pop('email_smtp_password', None)
    return jsonify(config_out)


@app.route('/api/validate_key', methods=['POST'])
def validate_key():
    """Test an AbuseIPDB key by checking a known safe IP (1.1.1.1)."""
    key = request.json.get('api_key', '').strip()
    if not key:
        return jsonify({"valid": False, "message": "API key is empty"})
    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Accept': 'application/json', 'Key': key}
        params = {'ipAddress': '1.1.1.1', 'maxAgeInDays': '1'}
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        if resp.status_code == 200:
            return jsonify({"valid": True, "message": "Key is valid ✓"})
        elif resp.status_code == 422:
            return jsonify({"valid": False, "message": "Invalid key format"})
        elif resp.status_code == 429:
            return jsonify({"valid": True,  "message": "Rate-limited — but key appears valid ✓"})
        else:
            return jsonify({"valid": False, "message": f"AbuseIPDB returned {resp.status_code}"})
    except requests.exceptions.Timeout:
        return jsonify({"valid": False, "message": "Request timed out — check your network"})
    except Exception as e:
        return jsonify({"valid": False, "message": str(e)})

@app.route('/api/test_email', methods=['POST'])
def test_email():
    """Send a test email to verify SMTP configuration (FR-10)."""
    success, message = send_test_email()
    return jsonify({"success": success, "message": message})

@app.route('/api/send_daily_summary', methods=['POST'])
def trigger_daily_summary():
    """Manually trigger a daily summary email."""
    send_daily_summary()
    return jsonify({"status": "success", "message": "Daily summary email triggered."})

# ============================================================================
# Replace your existing /api/stats route in app.py with this version
# Adds: timeline data, top attacker, country breakdown for map
# ============================================================================

@app.route('/api/stats')
def get_stats():
    """Get dashboard statistics with enhanced data for charts and map."""
    source_filter = request.args.get('source', 'all')
    
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    
    # Build WHERE clause for source filtering
    source_clause = ""
    source_params = []
    if source_filter in ('simulation', 'internet'):
        source_clause = " WHERE source = ?"
        source_params = [source_filter]
    
    # Helper to build AND clause when WHERE already exists
    def and_clause():
        return " AND " if source_clause else " WHERE "
    
    # Total attacks
    cursor.execute(f"SELECT COUNT(*) FROM attacks{source_clause}", source_params)
    total = cursor.fetchone()[0]
    
    # Unique IPs
    cursor.execute(f"SELECT COUNT(DISTINCT source_ip) FROM attacks{source_clause}", source_params)
    unique = cursor.fetchone()[0]
    
    # Unique countries
    q = f"SELECT COUNT(DISTINCT country_code) FROM attacks{source_clause}{and_clause() if source_clause else ' WHERE '}country_code IS NOT NULL"
    if source_filter in ('simulation', 'internet'):
        cursor.execute(q, source_params)
    else:
        cursor.execute("SELECT COUNT(DISTINCT country_code) FROM attacks WHERE country_code IS NOT NULL")
    countries = cursor.fetchone()[0]
    
    # Last 24 hours
    q = f"SELECT COUNT(*) FROM attacks{source_clause}{and_clause() if source_clause else ' WHERE '}replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')"
    if source_filter in ('simulation', 'internet'):
        cursor.execute(q, source_params)
    else:
        cursor.execute("SELECT COUNT(*) FROM attacks WHERE replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')")
    last_24h = cursor.fetchone()[0]
    avg_hr = round(last_24h / 24, 1) if last_24h > 0 else 0
    
    # Critical alerts (score >= 75)
    q = f"SELECT COUNT(*) FROM attacks{source_clause}{and_clause() if source_clause else ' WHERE '}abuse_score >= 75"
    if source_filter in ('simulation', 'internet'):
        cursor.execute(q, source_params)
    else:
        cursor.execute("SELECT COUNT(*) FROM attacks WHERE abuse_score >= 75")
    critical = cursor.fetchone()[0]
    
    # Attack type breakdown
    cursor.execute(f"""
        SELECT attack_type, COUNT(*) as count 
        FROM attacks{source_clause}
        GROUP BY attack_type 
        ORDER BY count DESC
    """, source_params)
    breakdown = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Manufacturer breakdown
    q = f"""
        SELECT manufacturer, COUNT(*) as count 
        FROM attacks{source_clause}{and_clause() if source_clause else ' WHERE '}manufacturer IS NOT NULL
        GROUP BY manufacturer 
        ORDER BY count DESC 
        LIMIT 6
    """
    if source_filter in ('simulation', 'internet'):
        cursor.execute(q, source_params)
    else:
        cursor.execute("""
            SELECT manufacturer, COUNT(*) as count 
            FROM attacks 
            WHERE manufacturer IS NOT NULL 
            GROUP BY manufacturer 
            ORDER BY count DESC 
            LIMIT 6
        """)
    manufacturers = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Country breakdown for map
    q = f"""
        SELECT country_code, COUNT(*) as count 
        FROM attacks{source_clause}{and_clause() if source_clause else ' WHERE '}country_code IS NOT NULL
        GROUP BY country_code 
        ORDER BY count DESC
    """
    if source_filter in ('simulation', 'internet'):
        cursor.execute(q, source_params)
    else:
        cursor.execute("""
            SELECT country_code, COUNT(*) as count 
            FROM attacks 
            WHERE country_code IS NOT NULL 
            GROUP BY country_code 
            ORDER BY count DESC
        """)
    country_breakdown = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Top attacker IP
    cursor.execute(f"""
        SELECT source_ip, COUNT(*) as count 
        FROM attacks{source_clause}
        GROUP BY source_ip 
        ORDER BY count DESC 
        LIMIT 1
    """, source_params)
    top_row = cursor.fetchone()
    top_attacker = {'ip': top_row[0], 'count': top_row[1]} if top_row else {'ip': '--', 'count': 0}
    
    # Timeline data (attacks per hour for last 24 hours)
    q = f"""
        SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
        FROM attacks{source_clause}{and_clause() if source_clause else ' WHERE '}replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')
        GROUP BY hour
        ORDER BY hour
    """
    if source_filter in ('simulation', 'internet'):
        cursor.execute(q, source_params)
    else:
        cursor.execute("""
            SELECT strftime('%H:00', timestamp) as hour, COUNT(*) as count
            FROM attacks
            WHERE replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')
            GROUP BY hour
            ORDER BY hour
        """)
    timeline = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Recent attacks (for feed)
    cursor.execute(f"""
        SELECT timestamp, source_ip, attack_type, abuse_score, country_code, manufacturer, source
        FROM attacks{source_clause}
        ORDER BY timestamp DESC 
        LIMIT 10
    """, source_params)
    recent = [
        {
            'time': row[0], 
            'ip': row[1], 
            'type': row[2], 
            'score': row[3], 
            'country': row[4] or 'Unknown',
            'vendor': row[5] or 'Generic',
            'source': row[6] or 'simulation'
        } 
        for row in cursor.fetchall()
    ]
    
    conn.close()
    
    # Determine threat level
    if critical >= 5 or last_24h >= 50:
        threat = 'HIGH'
    elif critical >= 2 or last_24h >= 20:
        threat = 'MEDIUM'
    else:
        threat = 'LOW'
    
    return jsonify({
        'total': total,
        'unique': unique,
        'countries': countries,
        'last_24h': last_24h,
        'avg_hr': avg_hr,
        'critical': critical,
        'threat': threat,
        'breakdown': breakdown,
        'manufacturers': manufacturers,
        'country_breakdown': country_breakdown,
        'top_attacker': top_attacker,
        'timeline': timeline,
        'recent': recent
    })

@app.route('/api/clear', methods=['POST'])
def clear_db():
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM attacks")
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/all_logs')
def get_all_logs():
    """Get all attack logs with full details for modal display."""
    period = request.args.get('period', 'all')
    attack_type = request.args.get('type', 'all')
    vendor = request.args.get('vendor', 'all')
    include_noise = request.args.get('include_noise', 'true') == 'true'
    source_filter = request.args.get('source', 'all')

    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    
    query = """
        SELECT 
            attack_id,
            timestamp, 
            source_ip, 
            http_method,
            url_path,
            payload,
            user_agent,
            abuse_score, 
            attack_type, 
            country_code, 
            manufacturer,
            source
        FROM attacks 
        WHERE 1=1
    """
    params = []

    # Filter by data source (simulation vs internet)
    if source_filter in ('simulation', 'internet'):
        query += " AND source = ?"
        params.append(source_filter)

    # Filter out background noise if requested
    if not include_noise:
        query += " AND (abuse_score >= 50 OR attack_type LIKE '%T1%')"

    if period == '1h':
        query += " AND replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 hour')"
    elif period == '24h':
        query += " AND replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')"
    elif period == '7d':
        query += " AND replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-7 days')"

    if attack_type != 'all':
        query += " AND attack_type LIKE ?"
        params.append(f"%{attack_type}%")

    if vendor != 'all':
        query += " AND manufacturer = ?"
        params.append(vendor)

    query += " ORDER BY timestamp DESC"
    
    cursor.execute(query, params)
    
    # Map all fields to dictionary
    columns = ['id', 'time', 'ip', 'method', 'path', 'payload', 'agent', 'score', 'type', 'country', 'vendor', 'source']
    logs = [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    conn.close()
    return jsonify(logs)


# ============================================================================
# EXPORT ENDPOINTS (FR-9 + NFR-S2: IP Anonymization on Export)
# ============================================================================

def _anonymize_ip(ip):
    """Mask the last octet of an IPv4 address (e.g. 192.168.10.129 → 192.168.10.xxx)."""
    if not ip:
        return ip
    parts = ip.split('.')
    if len(parts) == 4:
        parts[-1] = 'xxx'
        return '.'.join(parts)
    return ip  # Non-IPv4 (e.g. IPv6) returned as-is for safety


def _anonymize_payload(payload_str):
    """Find and mask any IPv4 addresses embedded in payload text."""
    if not payload_str:
        return payload_str
    import re
    return re.sub(
        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b',
        r'\1.xxx',
        payload_str
    )


def _fetch_export_data(anonymize=False):
    """Shared query logic for both CSV and JSON export (reuses get_all_logs filters)."""
    period = request.args.get('period', 'all')
    attack_type = request.args.get('type', 'all')
    include_noise = request.args.get('include_noise', 'true') == 'true'
    source_filter = request.args.get('source', 'all')

    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()

    query = """
        SELECT attack_id, timestamp, source_ip, http_method, url_path,
               payload, user_agent, abuse_score, attack_type,
               country_code, manufacturer, source
        FROM attacks WHERE 1=1
    """
    params = []

    if source_filter in ('simulation', 'internet'):
        query += " AND source = ?"
        params.append(source_filter)

    if not include_noise:
        query += " AND (abuse_score >= 50 OR attack_type LIKE '%T1%')"

    if period == '1h':
        query += " AND replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 hour')"
    elif period == '24h':
        query += " AND replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')"
    elif period == '7d':
        query += " AND replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-7 days')"

    if attack_type != 'all':
        query += " AND attack_type LIKE ?"
        params.append(f"%{attack_type}%")

    query += " ORDER BY timestamp DESC"
    cursor.execute(query, params)

    columns = ['id', 'timestamp', 'source_ip', 'http_method', 'url_path',
               'payload', 'user_agent', 'abuse_score', 'attack_type',
               'country_code', 'manufacturer', 'source']
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()

    # Apply anonymization if requested (NFR-S2)
    if anonymize:
        for row in rows:
            row['source_ip'] = _anonymize_ip(row.get('source_ip', ''))
            row['payload'] = _anonymize_payload(row.get('payload', ''))

    return rows


@app.route('/api/export/csv')
def export_csv():
    """Export filtered attack logs as CSV file with optional IP anonymization."""
    anonymize = request.args.get('anonymize', 'false') == 'true'
    rows = _fetch_export_data(anonymize=anonymize)

    import io, csv
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'id', 'timestamp', 'source_ip', 'http_method', 'url_path',
        'payload', 'user_agent', 'abuse_score', 'attack_type',
        'country_code', 'manufacturer', 'source'
    ])
    writer.writeheader()
    writer.writerows(rows)

    suffix = '_anonymized' if anonymize else ''
    filename = f'honeypot_attacks{suffix}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    from flask import Response
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@app.route('/api/export/json')
def export_json():
    """Export filtered attack logs as JSON file with optional IP anonymization."""
    anonymize = request.args.get('anonymize', 'false') == 'true'
    rows = _fetch_export_data(anonymize=anonymize)

    suffix = '_anonymized' if anonymize else ''
    filename = f'honeypot_attacks{suffix}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

    import json as json_lib
    from flask import Response
    return Response(
        json_lib.dumps(rows, indent=2, ensure_ascii=False),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


@app.route('/api/system_info')
def get_system_info():
    """Get system network information"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"
    
    return jsonify({
        "local_ip": local_ip,
        "bind_host": get_bind_host(honeypot_config),
        "port": honeypot_config['port'],
        "mode": honeypot_config['mode']
    })

@app.route('/api/clear_ip_cache', methods=['POST'])
def clear_ip_cache():
    '''Clear the IP intelligence cache table.'''
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM ip_intelligence')
    count = cursor.fetchone()[0]
    cursor.execute('DELETE FROM ip_intelligence')
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'cleared': count})

@app.route('/api/factory_reset', methods=['POST'])
def factory_reset():
    '''Factory reset - clear all data and reset config.'''
    import os
    
    # Clear attacks table
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM attacks')
    cursor.execute('DELETE FROM ip_intelligence')
    conn.commit()
    conn.close()
    
    # Reset config to defaults
    save_config(DEFAULT_CONFIG)
    
    return jsonify({'status': 'success', 'message': 'Factory reset complete'})

# ============================================================================
# REGISTER LAB MODULE
# ============================================================================
init_lab_module(
    app_config=honeypot_config,
    current_persona=current_persona,
    attack_sources=ATTACK_SOURCES,
    get_reputation_func=get_reputation_score,
    get_api_key_func=get_api_key
)
app.register_blueprint(lab_bp)

# Internet Mode module (middleware, honey routes, catch-all)
init_internet_module(
    app_config=honeypot_config,
    current_persona=current_persona,
    log_to_db_func=log_to_db,
    get_reputation_func=get_reputation_score,
    send_alert_func=send_alert
)
app.register_blueprint(internet_bp)

from forensic import forensic_bp
app.register_blueprint(forensic_bp)
from scripting import scripting_bp
app.register_blueprint(scripting_bp)

# Email notification module (FR-10)
init_notifier(app_config=honeypot_config, db_path='attacks.db')

# ============================================================================
# MAIN
# ============================================================================
if __name__ == '__main__':
    init_db()
    
    bind_host = get_bind_host(honeypot_config)
    port = honeypot_config['port']
    
    # ── Spoof Werkzeug's HTTP fingerprint (DYNAMIC) ──
    # This reads current_persona at response time, so changing
    # persona in Settings takes effect immediately for Nmap scans.
    WSGIRequestHandler.version_string = lambda self: VENDOR_HEADERS.get(
        current_persona.get('vendor', 'Generic'), 'GoAhead-Webs'
    )
    
    # ── Override Werkzeug's 400 error page template ──
    # Nmap sends binary probes (SMB, RTSP, SIP, TLS, etc.) to port 80.
    # These hit Werkzeug's HTTP parser BEFORE Flask, generating 400 errors.
    # The default Werkzeug template has a distinctive "Error response" title
    # and "Error code explanation" text that fingerprints Python.
    # This override makes those errors look like a generic embedded device.
    WSGIRequestHandler.error_message_format = (
        '<html><head><title>%(code)d</title></head>'
        '<body><h1>%(code)d %(message)s</h1></body></html>\r\n'
    )
    
    # Auto-detect local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "127.0.0.1"
    
    # Print startup banner (only in reloader child to avoid double-print)
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        print("=" * 60)
        print("🍯 IoT Honeypot")
        print("=" * 60)
        print(f"  Mode    : {honeypot_config['mode'].upper()}")
        print(f"  Flask   : {bind_host}:{port} (internal)")
        print(f"  Nginx   : {local_ip}:80 (HTTP) + :443 (HTTPS)")
        print(f"  Persona : {current_persona['name']}")
        _current_server = VENDOR_HEADERS.get(current_persona.get('vendor', 'Generic'), 'GoAhead-Webs')
        print(f"  Server  : {_current_server}")
        print(f"  Access  : http://{local_ip}")
        print(f"  Access  : https://{local_ip}")
        print("-" * 60)
        print(f"  Admin   : http://{local_ip}/honeypot-admin")
        print(f"  Login   : {honeypot_config.get('admin_username','admin')} / {honeypot_config.get('admin_password','fyp2026')}")
        print("-" * 60)
        print("  💡 Switch modes in Settings — no restart needed!")
        print("=" * 60)
    
    # debug=True enables hot-reload (file changes auto-restart)
    # Error handlers hide tracebacks from attackers in Internet Mode
    app.run(host=bind_host, port=port, threaded=True, debug=True)