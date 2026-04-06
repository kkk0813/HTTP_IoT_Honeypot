# ============================================================================
# test_honey_routes.py — Honey Route & Admin Protection Tests
# ============================================================================
# Tests the deception layer: bait endpoints that return convincing
# fake content, and admin path protection in Internet Mode.
#
# Uses Flask's built-in test client — no Nginx or real network needed.
#
# Run:  pytest tests/test_honey_routes.py -v
# ============================================================================

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# SECTION A: HONEY BAIT ROUTES
# ============================================================================
# These endpoints exist to attract and deceive scanners.
# Each should return a realistic response that wastes attacker time.
# ============================================================================

class TestHoneyRoutes:
    """Verify honey bait endpoints return convincing fake content."""

    def test_robots_txt_returns_200(self, client):
        """robots.txt should exist and contain Disallow entries."""
        response = client.get('/robots.txt')
        assert response.status_code == 200
        assert b'Disallow' in response.data

    def test_robots_txt_contains_bait_paths(self, client):
        """robots.txt should list sensitive-looking paths to lure scanners."""
        response = client.get('/robots.txt')
        body = response.data.decode()
        assert '/admin' in body
        assert '/config' in body
        assert '/backup' in body

    def test_sitemap_xml_returns_200(self, client):
        """Fake sitemap should return valid XML."""
        response = client.get('/sitemap.xml')
        assert response.status_code == 200
        assert b'<?xml' in response.data
        assert b'urlset' in response.data

    def test_env_file_returns_fake_credentials(self, client):
        """Fake .env should contain realistic-looking (but fake) secrets."""
        response = client.get('/.env')
        assert response.status_code == 200
        body = response.data.decode()
        assert 'DB_PASSWORD' in body
        assert 'SECRET_KEY' in body
        assert 'API_KEY' in body

    def test_config_bin_returns_binary(self, client):
        """Fake firmware/config downloads should return binary data."""
        response = client.get('/config.bin')
        assert response.status_code == 200
        assert response.content_type == 'application/octet-stream'
        assert len(response.data) > 0

    def test_backup_tar_gz_returns_binary(self, client):
        response = client.get('/backup.tar.gz')
        assert response.status_code == 200
        assert response.content_type == 'application/gzip'


# ============================================================================
# SECTION B: LOGIN PAGE RESPONSES
# ============================================================================
# The IoT login page should render without errors and contain
# expected elements.
# ============================================================================

class TestLoginPage:
    """Verify the attacker-facing login page renders correctly."""

    def test_root_returns_login_page(self, client):
        """GET / should return the login page with a form."""
        response = client.get('/')
        assert response.status_code == 200
        assert b'<form' in response.data or b'login' in response.data.lower()

    def test_post_login_redirects(self, client):
        """POST /login should accept credentials and redirect (not crash)."""
        response = client.post('/login', data={
            'username': 'admin',
            'password': 'test'
        }, follow_redirects=False)
        # Should redirect back to login with error flag
        assert response.status_code in (302, 301, 200)


# ============================================================================
# SECTION C: ADMIN PATH PROTECTION (Internet Mode)
# ============================================================================
# In Internet Mode, admin pages should be hidden from attackers.
# Unauthenticated requests should receive vendor-styled 404s.
# ============================================================================

class TestAdminProtection:
    """Verify admin pages are protected from unauthenticated access."""

    def test_dashboard_requires_auth(self, client):
        """Unauthenticated GET /dashboard should not expose admin content."""
        response = client.get('/dashboard')
        # Should either redirect to /honeypot-admin or return 404
        assert response.status_code in (302, 401, 404)

    def test_logs_requires_auth(self, client):
        response = client.get('/logs')
        assert response.status_code in (302, 401, 404)

    def test_settings_requires_auth(self, client):
        response = client.get('/settings')
        assert response.status_code in (302, 401, 404)

    def test_api_stats_requires_auth(self, client):
        response = client.get('/api/stats')
        assert response.status_code in (302, 401, 404)

    def test_honeypot_admin_returns_401(self, client):
        """/honeypot-admin without credentials should prompt for login."""
        response = client.get('/honeypot-admin')
        # Should return 401 with WWW-Authenticate header or redirect
        assert response.status_code in (302, 401)


# ============================================================================
# SECTION D: CATCH-ALL 404 RESPONSES
# ============================================================================
# Unknown paths should return a response (either default or vendor-styled).
# The catch-all route captures directory enumeration probes.
# ============================================================================

class TestCatchAll:
    """Verify unknown paths return proper responses."""

    def test_random_path_does_not_crash(self, client):
        """Random paths should return a response, not a 500 error."""
        response = client.get('/this/path/does/not/exist')
        assert response.status_code != 500

    def test_common_scan_path(self, client):
        """Common scanner probe paths should not crash the server."""
        scan_paths = ['/wp-login.php', '/administrator', '/solr/admin',
                      '/actuator/health', '/.git/HEAD']
        for path in scan_paths:
            response = client.get(path)
            assert response.status_code != 500, f"Server error on {path}"