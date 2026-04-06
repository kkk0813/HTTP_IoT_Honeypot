# ============================================================================
# conftest.py — Shared pytest fixtures for the IoT Honeypot test suite
# ============================================================================
# Provides:
#   - Flask test client (for route/integration tests)
#   - FakeRequest helper (for internet mode classifier tests)
#   - Temporary database setup
# ============================================================================

import pytest
import sys
import os
import sqlite3
import tempfile

# Add project root to path so imports work regardless of where pytest runs
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ============================================================================
# FAKE REQUEST OBJECT (for testing _classify_attack in internet_routes.py)
# ============================================================================
class FakeRequest:
    """
    Lightweight mock of Flask's request object.
    Only includes the fields that _classify_attack() actually reads:
    path, method, and headers (specifically User-Agent).
    """
    def __init__(self, path='/', method='GET', user_agent='Mozilla/5.0'):
        self.path = path
        self.method = method
        self.headers = {'User-Agent': user_agent}


# ============================================================================
# FLASK TEST CLIENT FIXTURE
# ============================================================================
@pytest.fixture
def client():
    """
    Create a Flask test client for route-level testing.
    Uses the real app but with testing mode enabled.
    The test client simulates HTTP requests without needing
    Nginx or a running server.
    """
    from app import app

    app.config['TESTING'] = True
    # Disable CSRF and session security for testing
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        yield client


# ============================================================================
# DATABASE FIXTURE (fresh database for each test that needs it)
# ============================================================================
@pytest.fixture
def fresh_db(tmp_path):
    """
    Create a fresh temporary SQLite database for tests that
    need to verify database operations without affecting
    the real attacks.db.
    """
    db_path = str(tmp_path / 'test_attacks.db')
    conn = sqlite3.connect(db_path)
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
            last_updated DATETIME,
            usage_type TEXT DEFAULT 'Unknown'
        )
    ''')
    conn.commit()
    conn.close()
    yield db_path