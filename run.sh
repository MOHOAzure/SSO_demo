#!/bin/bash

# Kill any processes currently using the ports
kill -9 $(lsof -t -i:8000) 2>/dev/null
kill -9 $(lsof -t -i:8001) 2>/dev/null
kill -9 $(lsof -t -i:8002) 2>/dev/null

echo "🚀 Starting SSO System - Stage 2 (Complete Security Implementation)"
echo ""
echo "📋 Services:"
echo "  • IdP Server: http://localhost:8000"
echo "  • Client 1:   http://localhost:8001" 
echo "  • Client 2:   http://localhost:8002"
echo ""
echo "⚠️  Please visit Client URLs in your browser (do not click callback URLs in logs)"
echo ""
echo "🔒 Security Features:"
echo "  ✅ PKCE (Proof Key for Code Exchange)"
echo "  ✅ State parameter (CSRF protection)"
echo "  ✅ Nonce parameter (Replay attack protection)"
echo "  ✅ RS256 signed JWT tokens"
echo "  ✅ JWKS endpoint for public key distribution"
echo "  ✅ Secure signed session cookies"
echo "  ✅ Security headers (CSP, X-Frame-Options, etc.)"
echo ""

# Activate virtual environment if it exists
if [ -d ".venv" ]; then
    echo "Activating virtual environment..."
    source .venv/bin/activate
fi

# Install dependencies if needed
echo "Checking dependencies..."
pip install -r requirements.txt > /dev/null 2>&1

echo ""
echo "Starting services..."

# Start IdP on port 8000
python idp_app.py &
IDP_PID=$!

# Start Client 1 on port 8001
python client1_app.py &
CLIENT1_PID=$!

# Start Client 2 on port 8002  
python client2_app.py &
CLIENT2_PID=$!

echo "IdP running on http://localhost:8000 (PID: $IDP_PID)"
echo "Client 1 running on http://localhost:8001 (PID: $CLIENT1_PID)"
echo "Client 2 running on http://localhost:8002 (PID: $CLIENT2_PID)"

# Function to clean up background processes on exit
cleanup() {
    echo "Shutting down services..."
    kill $IDP_PID
    kill $CLIENT1_PID
    kill $CLIENT2_PID
    exit
}

# Trap Ctrl+C and call cleanup
trap cleanup INT

# Wait for all background processes to complete
wait
