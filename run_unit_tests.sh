#!/bin/bash
# Run unit tests (no services required)

echo "🧪 Run Unit Tests (Unit Tests)"
echo "================================"
echo ""

# Activate virtual environment if exists
if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

python -m pytest tests/unit/test_unit_security.py tests/unit/test_logging.py -v --tb=short --color=yes

echo ""
echo "✅ Unit Tests Completed"
