# Tests

Automated test suite for the IoT Honeypot system using [pytest](https://docs.pytest.org/).

## Test Coverage

| File | Tests | What It Covers |
|---|---|---|
| `test_classifier.py` | 60 | Attack classification engine — all 8 attack types, edge cases, and classifier priority ordering |
| `test_honey_routes.py` | 15 | Honey bait endpoints, login page responses, admin path protection, catch-all 404 stability |
| `test_rate_limiter.py` | 7 | Sliding window rate limiter — threshold enforcement, per-IP isolation, stealth 404 responses |

**Total: 82 automated test cases**

## Quick Start

```bash
# Install pytest
pip install pytest --break-system-packages

# Run all tests
pytest tests/ -v

# Run a specific test file
pytest tests/test_classifier.py -v

# Run a specific test class
pytest tests/test_classifier.py::TestInternetSQLi -v
```

## Notes

- `test_classifier.py` and `test_rate_limiter.py` test functions directly — no running server needed.
- `test_honey_routes.py` uses Flask's built-in test client — no Nginx or network required.
- Tests do not modify the production `attacks.db` database.