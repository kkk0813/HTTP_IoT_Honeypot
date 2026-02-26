# ============================================================================
# notifier.py - Email Notification Module (FR-10)
# ============================================================================
# Handles: Real-time attack alerts and on-demand daily summary emails.
# Uses Python's built-in smtplib — no external dependencies.
# All alert emails are sent in background threads so the honeypot response
# to attackers is never delayed (keeps deception realistic).
# ============================================================================
# Architecture:
#   send_alert()        → spawns a daemon thread → sends email via Gmail SMTP
#   send_daily_summary() → queries SQLite for last 24h stats → sends email
#   send_test_email()   → synchronous test to verify SMTP config
# ============================================================================

import smtplib
import sqlite3
import threading
import time
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logger = logging.getLogger('honeypot.notifier')

# ============================================================================
# MODULE STATE (injected by init_notifier from app.py)
# ============================================================================
_app_config = {}
_db_path = 'attacks.db'

# Cooldown tracker: prevents email flood for same IP
# { 'ip_address': last_alert_timestamp }
_alert_cooldown = {}
COOLDOWN_SECONDS = 300  # 5-minute cooldown per IP


def init_notifier(app_config, db_path='attacks.db'):
    """Called once from app.py to inject shared config reference."""
    global _app_config, _db_path
    _app_config = app_config
    _db_path = db_path


# ============================================================================
# CORE EMAIL SENDER (runs inside background thread)
# ============================================================================
def _send_email(subject, html_body):
    """
    Send an email via Gmail SMTP using App Password.
    This function blocks for 1-2 seconds (network I/O), so it must
    ALWAYS be called from a background thread, never from a route handler.
    
    Returns True on success, False on failure.
    """
    sender = _app_config.get('email_smtp_address', '').strip()
    password = _app_config.get('email_smtp_password', '').strip()
    recipient = _app_config.get('email_recipient', '').strip()

    if not all([sender, password, recipient]):
        logger.warning('Email not configured — missing sender, password, or recipient.')
        return False

    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f'IoT Honeypot <{sender}>'
        msg['To'] = recipient
        msg['Subject'] = subject

        msg.attach(MIMEText(html_body, 'html'))

        # Gmail SMTP with TLS (port 587)
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(sender, password)
            server.sendmail(sender, recipient, msg.as_string())

        logger.info(f'Email sent: {subject}')
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error('SMTP auth failed — check Gmail address and App Password.')
        return False
    except smtplib.SMTPException as e:
        logger.error(f'SMTP error: {e}')
        return False
    except Exception as e:
        logger.error(f'Email send failed: {e}')
        return False


# ============================================================================
# REAL-TIME ALERT (FR-10: High-severity attack notification)
# ============================================================================
def send_alert(attack_data):
    """
    Called from internet_routes.py after logging a high-severity attack.
    Checks if alerts are enabled and abuse_score >= threshold, then
    sends an email in a background thread.
    
    attack_data dict: {
        'ip', 'method', 'path', 'attack_type', 'abuse_score',
        'country', 'user_agent', 'timestamp', 'payload'
    }
    """
    if not _app_config.get('email_alerts_enabled', False):
        return

    score = attack_data.get('abuse_score', 0)

    # Cooldown check — don't spam for same IP (5 min gap)
    ip = attack_data.get('ip', 'unknown')
    now = time.time()
    last_alert = _alert_cooldown.get(ip, 0)
    if now - last_alert < COOLDOWN_SECONDS:
        return
    _alert_cooldown[ip] = now

    # Build email in background thread
    def _send():
        subject = f'🚨 Honeypot Alert — {attack_data.get("attack_type", "Unknown")} from {ip}'

        # Determine severity color based on attack type (zero trust — score may be 0)
        attack_type = attack_data.get('attack_type', '')
        high_severity_types = ['SQL Injection', 'Command Injection', 'Malicious Upload', 'XSS']
        if any(t in attack_type for t in high_severity_types) or score >= 75:
            severity = 'CRITICAL'
            color = '#dc2626'
            bg = '#fef2f2'
        elif 'Brute Force' in attack_type or score >= 50:
            severity = 'HIGH'
            color = '#ea580c'
            bg = '#fff7ed'
        else:
            severity = 'MEDIUM'
            color = '#ca8a04'
            bg = '#fefce8'

        html = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
            <div style="background:{color};color:white;padding:16px 24px;border-radius:8px 8px 0 0">
                <h2 style="margin:0;font-size:18px">🚨 Honeypot Alert — {severity}</h2>
                <p style="margin:4px 0 0;font-size:12px;opacity:0.9">
                    {attack_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
                </p>
            </div>
            
            <div style="background:{bg};padding:20px 24px;border:1px solid #e5e7eb;border-top:none">
                <table style="width:100%;border-collapse:collapse;font-size:14px">
                    <tr>
                        <td style="padding:8px 0;font-weight:bold;color:#374151;width:140px">Attack Type</td>
                        <td style="padding:8px 0;color:#111827">
                            <span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:12px">
                                {attack_data.get('attack_type', 'Unknown')}
                            </span>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;font-weight:bold;color:#374151">Source IP</td>
                        <td style="padding:8px 0;font-family:monospace;color:#111827">{ip}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;font-weight:bold;color:#374151">Abuse Score</td>
                        <td style="padding:8px 0;color:{color};font-weight:bold">{score}/100</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;font-weight:bold;color:#374151">Country</td>
                        <td style="padding:8px 0">{attack_data.get('country', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;font-weight:bold;color:#374151">HTTP Method</td>
                        <td style="padding:8px 0;font-family:monospace">{attack_data.get('method', '?')}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;font-weight:bold;color:#374151">Target Path</td>
                        <td style="padding:8px 0;font-family:monospace">{attack_data.get('path', '/')}</td>
                    </tr>
                    <tr>
                        <td style="padding:8px 0;font-weight:bold;color:#374151">User-Agent</td>
                        <td style="padding:8px 0;font-size:12px;color:#6b7280;word-break:break-all">
                            {attack_data.get('user_agent', 'Unknown')[:120]}
                        </td>
                    </tr>
                </table>
            </div>
            
            <div style="background:#f9fafb;padding:12px 24px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px">
                <p style="margin:0;font-size:11px;color:#9ca3af">
                    IoT Honeypot — Automated alert. Review the dashboard for full details.
                </p>
            </div>
        </div>
        """

        _send_email(subject, html)

    thread = threading.Thread(target=_send, daemon=True)
    thread.start()


# ============================================================================
# DAILY SUMMARY EMAIL (FR-10: Scheduled digest)
# ============================================================================
def send_daily_summary():
    """
    Query the database for last-24h statistics and send a summary email.
    Called manually via the 'Send Summary Now' button in Settings.
    """

    try:
        conn = sqlite3.connect(_db_path)
        cursor = conn.cursor()

        # Total attacks in last 24h
        cursor.execute("""
            SELECT COUNT(*) FROM attacks 
            WHERE replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')
        """)
        total_24h = cursor.fetchone()[0]

        # Unique IPs in last 24h
        cursor.execute("""
            SELECT COUNT(DISTINCT source_ip) FROM attacks 
            WHERE replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')
        """)
        unique_ips = cursor.fetchone()[0]

        # Critical attacks (score >= 75)
        cursor.execute("""
            SELECT COUNT(*) FROM attacks 
            WHERE replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')
            AND abuse_score >= 75
        """)
        critical = cursor.fetchone()[0]

        # Attack type breakdown
        cursor.execute("""
            SELECT attack_type, COUNT(*) as cnt FROM attacks
            WHERE replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')
            GROUP BY attack_type ORDER BY cnt DESC LIMIT 8
        """)
        type_breakdown = cursor.fetchall()

        # Top 5 attacking IPs
        cursor.execute("""
            SELECT source_ip, COUNT(*) as cnt, 
                   MAX(abuse_score) as max_score, country_code
            FROM attacks
            WHERE replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')
            GROUP BY source_ip ORDER BY cnt DESC LIMIT 5
        """)
        top_ips = cursor.fetchall()

        # Country breakdown (top 5)
        cursor.execute("""
            SELECT country_code, COUNT(*) as cnt FROM attacks
            WHERE replace(timestamp, 'T', ' ') > datetime('now', 'localtime', '-1 day')
            AND country_code IS NOT NULL AND country_code != 'Unknown'
            GROUP BY country_code ORDER BY cnt DESC LIMIT 5
        """)
        top_countries = cursor.fetchall()

        conn.close()

    except Exception as e:
        logger.error(f'Daily summary DB query failed: {e}')
        return

    # Determine threat level
    if critical >= 5 or total_24h >= 50:
        threat = 'HIGH'
        threat_color = '#dc2626'
        threat_bg = '#fef2f2'
    elif critical >= 2 or total_24h >= 20:
        threat = 'MEDIUM'
        threat_color = '#ea580c'
        threat_bg = '#fff7ed'
    else:
        threat = 'LOW'
        threat_color = '#16a34a'
        threat_bg = '#f0fdf4'

    # Build attack type rows
    type_rows = ''
    for atype, count in type_breakdown:
        type_rows += f"""
        <tr>
            <td style="padding:6px 12px;border-bottom:1px solid #f3f4f6;font-size:13px">{atype}</td>
            <td style="padding:6px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;text-align:right;font-weight:bold">{count}</td>
        </tr>"""

    # Build top IP rows
    ip_rows = ''
    for ip, count, max_score, country in top_ips:
        score_color = '#dc2626' if max_score >= 75 else '#ea580c' if max_score >= 50 else '#6b7280'
        ip_rows += f"""
        <tr>
            <td style="padding:6px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;font-family:monospace">{ip}</td>
            <td style="padding:6px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;text-align:center">{country or '?'}</td>
            <td style="padding:6px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;text-align:center;font-weight:bold;color:{score_color}">{max_score}</td>
            <td style="padding:6px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;text-align:right;font-weight:bold">{count}</td>
        </tr>"""

    # Build country rows
    country_rows = ''
    for country, count in top_countries:
        country_rows += f"""
        <tr>
            <td style="padding:6px 12px;border-bottom:1px solid #f3f4f6;font-size:13px">{country}</td>
            <td style="padding:6px 12px;border-bottom:1px solid #f3f4f6;font-size:13px;text-align:right;font-weight:bold">{count}</td>
        </tr>"""

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M')
    subject = f'📊 Honeypot Daily Summary — {total_24h} attacks ({now_str})'

    html = f"""
    <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto">
        <!-- Header -->
        <div style="background:linear-gradient(135deg,#1e3a5f,#2563eb);color:white;padding:20px 24px;border-radius:8px 8px 0 0">
            <h2 style="margin:0;font-size:20px">📊 Daily Honeypot Summary</h2>
            <p style="margin:4px 0 0;font-size:12px;opacity:0.85">Report generated: {now_str}</p>
        </div>

        <!-- Stat Cards -->
        <div style="background:#f8fafc;padding:20px 24px;border:1px solid #e5e7eb;border-top:none">
            <table style="width:100%;border-collapse:collapse">
                <tr>
                    <td style="text-align:center;padding:12px">
                        <div style="font-size:28px;font-weight:bold;color:#1e3a5f">{total_24h}</div>
                        <div style="font-size:11px;color:#6b7280;text-transform:uppercase">Total Attacks</div>
                    </td>
                    <td style="text-align:center;padding:12px">
                        <div style="font-size:28px;font-weight:bold;color:#7c3aed">{unique_ips}</div>
                        <div style="font-size:11px;color:#6b7280;text-transform:uppercase">Unique IPs</div>
                    </td>
                    <td style="text-align:center;padding:12px">
                        <div style="font-size:28px;font-weight:bold;color:#dc2626">{critical}</div>
                        <div style="font-size:11px;color:#6b7280;text-transform:uppercase">Critical</div>
                    </td>
                    <td style="text-align:center;padding:12px">
                        <div style="font-size:14px;font-weight:bold;color:{threat_color};background:{threat_bg};padding:8px 12px;border-radius:6px">{threat}</div>
                        <div style="font-size:11px;color:#6b7280;text-transform:uppercase;margin-top:4px">Threat Level</div>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Attack Types -->
        <div style="padding:16px 24px;border:1px solid #e5e7eb;border-top:none">
            <h3 style="margin:0 0 12px;font-size:14px;color:#374151">Attack Type Breakdown</h3>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#f9fafb">
                    <th style="padding:8px 12px;text-align:left;font-size:11px;color:#6b7280;text-transform:uppercase">Type</th>
                    <th style="padding:8px 12px;text-align:right;font-size:11px;color:#6b7280;text-transform:uppercase">Count</th>
                </tr>
                {type_rows if type_rows else '<tr><td colspan="2" style="padding:12px;text-align:center;color:#9ca3af;font-size:13px">No attacks recorded</td></tr>'}
            </table>
        </div>

        <!-- Top Attackers -->
        <div style="padding:16px 24px;border:1px solid #e5e7eb;border-top:none">
            <h3 style="margin:0 0 12px;font-size:14px;color:#374151">Top Attacking IPs</h3>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#f9fafb">
                    <th style="padding:8px 12px;text-align:left;font-size:11px;color:#6b7280;text-transform:uppercase">IP Address</th>
                    <th style="padding:8px 12px;text-align:center;font-size:11px;color:#6b7280;text-transform:uppercase">Country</th>
                    <th style="padding:8px 12px;text-align:center;font-size:11px;color:#6b7280;text-transform:uppercase">Score</th>
                    <th style="padding:8px 12px;text-align:right;font-size:11px;color:#6b7280;text-transform:uppercase">Attacks</th>
                </tr>
                {ip_rows if ip_rows else '<tr><td colspan="4" style="padding:12px;text-align:center;color:#9ca3af;font-size:13px">No attackers recorded</td></tr>'}
            </table>
        </div>

        <!-- Geographic Origins -->
        <div style="padding:16px 24px;border:1px solid #e5e7eb;border-top:none">
            <h3 style="margin:0 0 12px;font-size:14px;color:#374151">Top Attack Origins</h3>
            <table style="width:100%;border-collapse:collapse">
                <tr style="background:#f9fafb">
                    <th style="padding:8px 12px;text-align:left;font-size:11px;color:#6b7280;text-transform:uppercase">Country</th>
                    <th style="padding:8px 12px;text-align:right;font-size:11px;color:#6b7280;text-transform:uppercase">Attacks</th>
                </tr>
                {country_rows if country_rows else '<tr><td colspan="2" style="padding:12px;text-align:center;color:#9ca3af;font-size:13px">No geographic data</td></tr>'}
            </table>
        </div>

        <!-- Footer -->
        <div style="background:#f9fafb;padding:12px 24px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px">
            <p style="margin:0;font-size:11px;color:#9ca3af">
                IoT Honeypot — Automated daily summary. Review the dashboard for full details and raw logs.
            </p>
        </div>
    </div>
    """

    # Send in background thread so the API endpoint responds immediately
    def _send():
        _send_email(subject, html)

    thread = threading.Thread(target=_send, daemon=True)
    thread.start()


# ============================================================================
# TEST EMAIL (called from /api/test_email endpoint)
# ============================================================================
def send_test_email():
    """
    Send a test email to verify SMTP configuration.
    Returns (success: bool, message: str).
    Called synchronously from the API endpoint (not in background).
    """
    subject = '✅ IoT Honeypot — Test Email'
    html = """
    <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
        <div style="background:#16a34a;color:white;padding:16px 24px;border-radius:8px 8px 0 0">
            <h2 style="margin:0;font-size:18px">✅ Email Configuration Verified</h2>
        </div>
        <div style="padding:20px 24px;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px">
            <p style="color:#374151;font-size:14px;margin:0 0 8px">
                Your IoT Honeypot email notifications are configured correctly.
            </p>
            <p style="color:#6b7280;font-size:13px;margin:0 0 8px">
                You will receive:
            </p>
            <ul style="color:#6b7280;font-size:13px;margin:0;padding-left:20px">
                <li>Real-time alerts for high-severity attacks (if enabled)</li>
                <li>Daily summary reports (if enabled)</li>
            </ul>
            <hr style="border:none;border-top:1px solid #e5e7eb;margin:16px 0">
            <p style="margin:0;font-size:11px;color:#9ca3af">
                This is a test email from your IoT Honeypot system.
            </p>
        </div>
    </div>
    """

    success = _send_email(subject, html)
    if success:
        return True, 'Test email sent successfully! Check your inbox.'
    else:
        return False, 'Failed to send — check SMTP address, App Password, and recipient.'