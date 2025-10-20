#!/bin/bash
# Run integration tests (services must be started first)

echo "🧪 Run Integration Tests (Integration Tests)"
echo "======================================="
echo ""

# Activate virtual environment if exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# Check if services are running
if ! curl -s http://localhost:8000/ > /dev/null 2>&1; then
    echo "❌ Error: Services not running!"
    echo "Please run: ./run.sh first"
    exit 1
fi

echo "✅ Services running, starting tests..."
echo ""

pytest tests/integration/test_integration_*.py tests/integration/test_monitoring.py -v --tb=short --color=yes

echo ""
echo "✅ Integration Tests Completed"
