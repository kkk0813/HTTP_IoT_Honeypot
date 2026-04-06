# ============================================================================
# test_rate_limiter.py — Rate Limiting Engine Tests
# ============================================================================
# Tests the sliding window rate limiter in internet_routes.py.
# Verifies that:
#   - Requests below the threshold are allowed
#   - Requests above the threshold are blocked
#   - The sliding window expires old entries
#   - Disabling rate limiting allows all traffic
#
# Run:  pytest tests/test_rate_limiter.py -v
# ============================================================================

import pytest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import internet_routes


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset the rate limiter state before each test."""
    internet_routes._rate_limit_store = {}
    # Save original config
    original_config = dict(internet_routes._app_config)
    # Set default test config
    internet_routes._app_config = {
        'rate_limit_enabled': True,
        'max_requests_per_ip': 5,  # Low threshold for testing
    }
    yield
    # Restore original config
    internet_routes._app_config = original_config
    internet_routes._rate_limit_store = {}


class TestRateLimiter:
    """Core rate limiting logic tests."""

    def test_first_request_allowed(self):
        """First request from any IP should always be allowed."""
        assert internet_routes._check_rate_limit('10.0.0.1') is True

    def test_requests_below_threshold_allowed(self):
        """Requests within the limit should all be allowed."""
        ip = '10.0.0.2'
        for i in range(5):
            assert internet_routes._check_rate_limit(ip) is True, \
                f"Request {i+1} of 5 was blocked — should be allowed"

    def test_requests_above_threshold_blocked(self):
        """The 6th request (exceeding limit of 5) should be blocked."""
        ip = '10.0.0.3'
        # Use up the 5-request allowance
        for _ in range(5):
            internet_routes._check_rate_limit(ip)
        # 6th request should be blocked
        assert internet_routes._check_rate_limit(ip) is False

    def test_different_ips_independent(self):
        """Rate limits should be tracked per-IP, not globally."""
        # Exhaust limit for IP A
        for _ in range(5):
            internet_routes._check_rate_limit('10.0.0.10')
        assert internet_routes._check_rate_limit('10.0.0.10') is False

        # IP B should still be allowed
        assert internet_routes._check_rate_limit('10.0.0.11') is True

    def test_disabled_rate_limit_allows_all(self):
        """When rate limiting is disabled, all requests should pass."""
        internet_routes._app_config['rate_limit_enabled'] = False
        ip = '10.0.0.20'
        # Even 100 requests should all be allowed
        for i in range(100):
            assert internet_routes._check_rate_limit(ip) is True, \
                f"Request {i+1} blocked despite rate limiting being disabled"

    def test_sliding_window_expires_old_entries(self):
        """Entries older than 1 hour should be pruned from the window."""
        ip = '10.0.0.30'
        # Manually inject old timestamps (2 hours ago)
        old_time = time.time() - 7200
        internet_routes._rate_limit_store[ip] = [old_time] * 5

        # New request should be allowed because old entries are pruned
        assert internet_routes._check_rate_limit(ip) is True

    def test_configurable_threshold(self):
        """Rate limit threshold should respect the config value."""
        internet_routes._app_config['max_requests_per_ip'] = 3
        ip = '10.0.0.40'
        # 3 requests allowed
        for _ in range(3):
            assert internet_routes._check_rate_limit(ip) is True
        # 4th blocked
        assert internet_routes._check_rate_limit(ip) is False