# SSO Testing Guide

This document explains how to run unit tests and integration tests for the SSO system.

---

## Test Structure

```
tests/
├── __init__.py
├── test_unit_security.py            # Unit tests: Security functions (PKCE, JWT)
├── test_monitoring.py                # Unit tests: Monitoring endpoints
├── test_logging.py                   # Unit tests: Log structure
├── test_integration_sso.py           # Integration tests: Complete SSO flow
└── test_integration_monitoring.py    # Integration tests: Monitoring and business processes
```

---

## Test Categories

### Unit Tests
**Features**: No server required, test independent functions and modules

**Includes**:
- `test_unit_security.py`: PKCE verification, cryptographic functions
- `test_monitoring.py`: Prometheus metrics endpoint format validation
- `test_logging.py`: JSON log structure validation

**Execution**:
```bash
# Run all unit tests
pytest tests/test_unit_security.py tests/test_monitoring.py tests/test_logging.py -v

# Or run single file only
pytest tests/test_unit_security.py -v
```

### Integration Tests
**Features**: Requires running complete SSO services (IdP + Clients)

**Includes**:
- `test_integration_sso.py`: Complete SSO authentication flow, session management, security headers
- `test_integration_monitoring.py`: Integration of monitoring metrics and business processes

**Execution**:
```bash
# 1. Start services first
./run.sh

# 2. Run integration tests in another terminal
pytest tests/test_integration_sso.py tests/test_integration_monitoring.py -v
```

---

## Quick Execution Commands

### Method 1: Run Separately

```bash
# Unit tests (no service required)
pytest tests/test_unit_security.py -v --tb=short

# Integration tests (requires ./run.sh first)
pytest tests/test_integration_sso.py -v --tb=short
pytest tests/test_integration_monitoring.py -v --tb=short
```

### Method 2: Use Convenience Scripts

```bash
# Run unit tests only (no services required)
chmod +x run_unit_tests.sh
./run_unit_tests.sh

# Run integration tests (requires ./run.sh first)
chmod +x run_integration_tests.sh
./run_integration_tests.sh

# Run monitoring verification (includes unit and integration tests)
chmod +x run_monitoring_tests.sh
./run_monitoring_tests.sh
```

### Method 3: Run All Tests

```bash
clear && ./run_unit_tests.sh && ./run_integration_tests.sh && ./run_monitoring_tests.sh

# Requires services to be running
pytest tests/ -v --tb=short
```

---

## Test Prerequisites

### Unit Tests
```bash
# Install test dependencies
uv pip install pytest prometheus-client python-json-logger

# No other preparation needed, run directly
pytest tests/test_unit_security.py -v
```

### Integration Tests
```bash
# 1. Install dependencies
uv pip install pytest prometheus-client python-json-logger requests

# 2. Start SSO services
./run.sh

# 3. Confirm services are running
curl http://localhost:8000  # IdP
curl http://localhost:8001  # Client1
curl http://localhost:8002  # Client2

# 4. Run tests
pytest tests/test_integration_sso.py -v
```

---

## Test Scope Description

### test_unit_security.py
- ✅ PKCE code_verifier generation
- ✅ PKCE code_challenge generation
- ✅ PKCE verification (success/failure scenarios)
- ✅ RFC 7636 test vector validation
- ✅ JWT structure validation

### test_monitoring.py
- ✅ `/metrics` endpoint accessibility
- ✅ Prometheus format validation
- ✅ Required metrics existence check
- ✅ Sensitive information leakage check
- ✅ Metrics endpoint performance test

### test_logging.py
- ✅ JSON log format definition
- ✅ Required field validation
- ✅ Event type definition
- ✅ Sensitive information filtering strategy

### test_integration_sso.py
- ✅ Service availability check
- ✅ OIDC standard endpoint validation (JWKS, OpenID Configuration)
- ✅ Login flow testing (success/failure)
- ✅ SSO cross-client testing
- ✅ Security header validation
- ✅ Session cookie security attributes

### test_integration_monitoring.py
- ✅ Login success/failure metrics tracking
- ✅ HTTP request latency tracking
- ✅ Callback processing metrics
- ✅ Dynamic client_id label validation
- ✅ Complete SSO flow monitoring validation

---

## Test Execution Examples

### Example 1: Run Unit Tests Only
```bash
$ pytest tests/test_unit_security.py -v

============================= test session starts ==============================
tests/test_unit_security.py::TestPKCEFunctions::test_code_verifier_generation PASSED
tests/test_unit_security.py::TestPKCEFunctions::test_code_challenge_generation PASSED
tests/test_unit_security.py::TestPKCEFunctions::test_pkce_verification_success PASSED
tests/test_unit_security.py::TestPKCEFunctions::test_pkce_verification_failure_wrong_verifier PASSED

============================== 4 passed in 0.05s ===============================
```

### Example 2: Run Integration Tests (Requires Services Running)
```bash
$ ./run.sh  # Start services in one terminal

# In another terminal
$ pytest tests/test_integration_sso.py::TestServiceAvailability -v

============================= test session starts ==============================
tests/test_integration_sso.py::TestServiceAvailability::test_idp_service_running PASSED
tests/test_integration_sso.py::TestServiceAvailability::test_client1_service_running PASSED
tests/test_integration_sso.py::TestServiceAvailability::test_client2_service_running PASSED

============================== 3 passed in 0.15s ===============================
```

### Example 3: Run Specific Test Classes
```bash
# Test PKCE functions only
pytest tests/test_unit_security.py::TestPKCEFunctions -v

# Test monitoring endpoints only
pytest tests/test_monitoring.py::TestMonitoringEndpoints -v
```

### Example 4: View Detailed Failure Information
```bash
pytest tests/ -v --tb=long  # Show complete traceback
pytest tests/ -v -s         # Show print output
```

---

## Test Coverage (Optional)

```bash
# Install coverage
uv pip install pytest-cov

# Run tests and generate coverage report
pytest tests/ --cov=. --cov-report=html

# View report
open htmlcov/index.html
```

---

## Troubleshooting

### Problem: Integration tests fail "Connection refused"
**Cause**: SSO services not running

**Solution**:
```bash
# Check service status
curl http://localhost:8000  # Should return 200

# If not running, start services
./run.sh
```

### Problem: Unit tests fail "ModuleNotFoundError"
**Cause**: Missing dependencies or path issues

**Solution**:
```bash
# Install dependencies
uv pip install pytest prometheus-client python-json-logger

# Confirm running from project root directory
pwd  # Should be in /Users/hongbao_ye/Desktop/POC/SSO
```

### Problem: Monitoring tests can't find metrics
**Cause**: Metrics haven't generated data yet

**Solution**:
```bash
# Manually trigger some operations first
curl http://localhost:8000/
curl http://localhost:8001/

# Then run tests
pytest tests/test_monitoring.py -v
```

---

## Continuous Integration (CI) Configuration Reference

```yaml
# .github/workflows/test.yml
name: SSO Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: |
          pip install pytest prometheus-client python-json-logger
      - name: Run unit tests
        run: pytest tests/test_unit_security.py tests/test_monitoring.py tests/test_logging.py -v
  
  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: |
          pip install -r requirements.txt pytest
      - name: Start services
        run: ./run.sh &
      - name: Wait for services
        run: sleep 5
      - name: Run integration tests
        run: pytest tests/test_integration_sso.py tests/test_integration_monitoring.py -v
```

---

## Testing Best Practices

1. **Unit Tests First**: Run unit tests first to ensure basic functions are correct
2. **Isolated Test Environment**: Integration tests use independent test data
3. **Clean Test Data**: Each test should be independent, not relying on other test states
4. **Meaningful Assertions**: Assertion failures should clearly explain the problem
5. **Regular Execution**: Run complete tests after every code change

---

## Related Documentation

- [README_SSO_intro.md](README_SSO_intro.md) - SSO System Overview
- [README_SSO_monitoring.md](README_SSO_monitoring.md) - Monitoring Design Document
- [README_SSO_secure_solution.md](README_SSO_secure_solution.md) - Security Implementation Document
