#!/bin/bash

# SSO Monitoring Verification Script
# This script runs tests against RUNNING services without killing them

set -e  # Exit on error

echo "🧪 SSO Monitoring Verification Suite"
echo "======================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if services are running
echo "📡 Checking if services are running..."
check_service() {
    local service_name=$1
    local port=$2
    
    if curl -s "http://localhost:${port}/" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} ${service_name} (port ${port}) is running"
        return 0
    else
        echo -e "  ${RED}✗${NC} ${service_name} (port ${port}) is NOT running"
        return 1
    fi
}

services_ok=true
check_service "IdP" 8000 || services_ok=false
check_service "Client1" 8001 || services_ok=false
check_service "Client2" 8002 || services_ok=false

if [ "$services_ok" = false ]; then
    echo ""
    echo -e "${RED}ERROR: Not all services are running!${NC}"
    echo "Please start services with: ./run.sh"
    exit 1
fi

echo ""
echo -e "${GREEN}All services are running${NC}"
echo ""

# Verify dependencies
echo "📦 Checking test dependencies..."
if ! python -c "import pytest" 2>/dev/null; then
    echo -e "${YELLOW}Installing pytest...${NC}"
    uv pip install pytest
fi

if ! python -c "import prometheus_client" 2>/dev/null; then
    echo -e "${YELLOW}Installing prometheus-client and python-json-logger...${NC}"
    uv pip install prometheus-client python-json-logger
fi

# Re-activate virtual environment to ensure PATH is updated after installations
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

echo -e "${GREEN}Dependencies OK${NC}"
echo ""

# Quick metrics endpoint check
echo "🔍 Quick /metrics endpoint check..."
for service in "IdP:8000" "Client1:8001" "Client2:8002"; do
    name="${service%%:*}"
    port="${service##*:}"
    
    if curl -s "http://localhost:${port}/metrics" | head -5 | grep -q "# HELP"; then
        echo -e "  ${GREEN}✓${NC} ${name} /metrics endpoint responding"
    else
        echo -e "  ${RED}✗${NC} ${name} /metrics endpoint issue"
    fi
done

echo ""

# Run test suites
echo "🧪 Running Test Suites"
echo "======================"
echo ""

test_failed=false

# Unit tests for monitoring endpoints
echo "1️⃣  Running Monitoring Endpoint Tests..."
if pytest tests/integration/test_monitoring.py -v --tb=short --color=yes; then
    echo -e "${GREEN}✓ Monitoring endpoint tests passed${NC}"
else
    echo -e "${RED}✗ Monitoring endpoint tests failed${NC}"
    test_failed=true
fi
echo ""

# Unit tests for logging
echo "2️⃣  Running Structured Logging Tests..."
if pytest tests/unit/test_logging.py -v --tb=short --color=yes; then
    echo -e "${GREEN}✓ Structured logging tests passed${NC}"
else
    echo -e "${RED}✗ Structured logging tests failed${NC}"
    test_failed=true
fi
echo ""

# Integration tests
echo "3️⃣  Running Integration Tests with Monitoring..."
if pytest tests/integration/test_integration_monitoring.py -v --tb=short --color=yes; then
    echo -e "${GREEN}✓ Integration monitoring tests passed${NC}"
else
    echo -e "${RED}✗ Integration monitoring tests failed${NC}"
    test_failed=true
fi
echo ""

# Display sample metrics
echo "📊 Sample Metrics Output"
echo "========================"
echo ""

echo "IdP Metrics Sample:"
echo "-------------------"
curl -s http://localhost:8000/metrics | grep -E "(idp_login_attempts_total|idp_http_request_duration)" | head -10
echo ""

echo "Client1 Metrics Sample:"
echo "-----------------------"
curl -s http://localhost:8001/metrics | grep -E "(client_callback_total|client_http_request_duration)" | head -10
echo ""

# Final summary
echo "📋 Test Summary"
echo "==============="
echo ""

if [ "$test_failed" = true ]; then
    echo -e "${RED}❌ Some tests failed${NC}"
    echo ""
    echo "Services are still running. Check logs for details."
    exit 1
else
    echo -e "${GREEN}✅ All monitoring tests passed!${NC}"
    echo ""
    echo "Monitoring is properly configured:"
    echo "  • /metrics endpoints are accessible"
    echo "  • Prometheus metrics are being collected"
    echo "  • JSON structured logging is configured"
    echo ""
    echo "Next steps:"
    echo "  1. Perform manual SSO login flow"
    echo "  2. Check http://localhost:8000/metrics for updated counts"
    echo "  3. Review logs for JSON formatted output"
    exit 0
fi
