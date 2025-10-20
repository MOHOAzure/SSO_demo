#!/usr/bin/env python3
"""
Client 2 Application
Implements complete OIDC client security mechanisms with monitoring and observability:
- PKCE flow
- state parameter generation and validation
- nonce parameter generation and validation
- Standard id_token validation
- Secure session cookies
- Prometheus metrics monitoring
- Structured JSON logging
"""

import os
import hashlib
import secrets
import base64
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
import logging
from contextlib import asynccontextmanager
import time

import uvicorn
import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jose import jwt, JWTError
from cryptography.hazmat.primitives import serialization
from starlette.middleware.base import BaseHTTPMiddleware

# Prometheus metrics
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# Structured JSON logging
from pythonjsonlogger.json import JsonFormatter

# Configure JSON structured logging
logHandler = logging.StreamHandler()
formatter = JsonFormatter(
    '%(timestamp)s %(level)s %(service)s %(event)s %(message)s',
    rename_fields={"levelname": "level", "asctime": "timestamp"}
)
logHandler.setFormatter(formatter)
logger = logging.getLogger("Client2")
logger.addHandler(logHandler)

# Prometheus Metrics definitions
logger.setLevel(logging.INFO)

# Prometheus Metrics definitions
callback_total = Counter(
    'client_callback_total',
    'Total number of callback attempts',
    ['status', 'error_type', 'client']
)

idp_request_duration = Histogram(
    'client_idp_request_duration_seconds',
    'Duration of requests to IdP',
    ['endpoint', 'status', 'client'],
    buckets=[0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

session_verification_failures = Counter(
    'client_session_verification_failures_total',
    'Total number of session verification failures',
    ['reason', 'client']
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    load_keys()
    cache_idp_jwks()
    logger.info("Client2 started", extra={"event": "startup", "service": "client2"})
    yield
    # Shutdown
    logger.info("Client2 shutdown", extra={"event": "shutdown", "service": "client2"})

# Prometheus middleware
class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/metrics":
            return await call_next(request)
        
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        return response

app = FastAPI(title="Client 2 - Stage 3 (Monitoring)", lifespan=lifespan)
app.add_middleware(PrometheusMiddleware)
templates = Jinja2Templates(directory="templates")

# Configuration
CLIENT_ID = "client2"
REDIRECT_URI = "http://localhost:8002/callback"
IdP_BASE_URL = "http://localhost:8000"
CLIENT_BASE_URL = "http://localhost:8002"

# Load keys on application startup
CLIENT_PRIVATE_KEY = None
CLIENT_PUBLIC_KEY = None

# @app.on_event("startup") # REMOVED
def load_keys():
    """Load client RSA key pair"""
    global CLIENT_PRIVATE_KEY, CLIENT_PUBLIC_KEY
    try:
        private_key_path = f"client_{CLIENT_ID}_key.pem"
        with open(private_key_path, "rb") as f:
            CLIENT_PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)
        
        CLIENT_PUBLIC_KEY = CLIENT_PRIVATE_KEY.public_key()
        logger.info(f"Successfully loaded RSA keys for {CLIENT_ID}")
    except Exception as e:
        logger.error(f"Failed to load RSA keys: {e}")
        raise RuntimeError("Could not load RSA keys, application cannot start.") from e

# OIDC endpoints
IdP_AUTHORIZE_URL = f"{IdP_BASE_URL}/authorize"
IdP_TOKEN_URL = f"{IdP_BASE_URL}/token"
IdP_JWKS_URL = f"{IdP_BASE_URL}/.well-known/jwks.json"
IdP_LOGOUT_URL = f"{IdP_BASE_URL}/logout"

def generate_code_verifier() -> str:
    """Generate PKCE code_verifier (high entropy random string)"""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def generate_code_challenge(verifier: str) -> str:
    """Generate code_challenge from code_verifier"""
    digest = hashlib.sha256(verifier.encode('utf-8')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

def create_state_cookie(data: Dict) -> str:
    """Create one-time, signed state cookie for OIDC flow"""
    if not CLIENT_PRIVATE_KEY:
        raise RuntimeError("Client private key not loaded.")
        
    payload = {
        **data,
        "iss": CLIENT_BASE_URL,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5), # Short lifetime
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, CLIENT_PRIVATE_KEY, algorithm="RS256")

def verify_state_cookie(cookie_value: str) -> Optional[Dict]:
    """Verify state cookie"""
    if not CLIENT_PUBLIC_KEY:
        logger.error("Client public key not loaded, cannot verify state cookie.")
        return None
        
    try:
        payload = jwt.decode(
            cookie_value,
            CLIENT_PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=CLIENT_BASE_URL
        )
        return payload
    except JWTError as e:
        logger.warning(f"State cookie verification failed: {e}")
        return None

def create_session_cookie(data: Dict) -> str:
    """Create secure long-term session cookie - using RS256 signature"""
    if not CLIENT_PRIVATE_KEY:
        raise RuntimeError("Client private key not loaded.")
        
    payload = {
        **data,
        "iss": CLIENT_BASE_URL,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30), # 30 minutes lifetime
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, CLIENT_PRIVATE_KEY, algorithm="RS256")

def verify_session_cookie(cookie_value: str) -> Optional[Dict]:
    """Verify signed JWT session cookie"""
    if not CLIENT_PUBLIC_KEY:
        logger.error("Client public key not loaded, cannot verify session.")
        return None
        
    try:
        payload = jwt.decode(
            cookie_value,
            CLIENT_PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=CLIENT_BASE_URL
        )
        return payload
    except JWTError as e:
        logger.warning(f"Session cookie verification failed: {e}")
        return None

async def verify_session(request: Request) -> Optional[Dict]:
    """FastAPI dependency to verify session and return user information"""
    session_cookie = request.cookies.get("client_session")
    if not session_cookie:
        session_verification_failures.labels(reason='missing_cookie', client='client2').inc()
        return None
    
    session_data = verify_session_cookie(session_cookie)
    if not session_data:
        session_verification_failures.labels(reason='verification_failed', client='client2').inc()
        return None
    
    return session_data.get("user_info")

def get_idp_jwks() -> Dict:
    """Fetch JWKS public key set from IdP with retry mechanism"""
    max_retries = 5
    delay = 2  # seconds
    for attempt in range(max_retries):
        try:
            response = requests.get(IdP_JWKS_URL, timeout=5)
            response.raise_for_status()
            logger.info("Successfully fetched IdP JWKS.")
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.warning(f"Attempt {attempt + 1}/{max_retries} failed to fetch JWKS: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                logger.error("All attempts to fetch JWKS failed.")
                raise HTTPException(status_code=500, detail="Failed to fetch public keys from IdP after multiple retries.")

# Cache IdP JWKS on application startup
IDP_JWKS = {}
# @app.on_event("startup") # REMOVED
def cache_idp_jwks():
    global IDP_JWKS
    IDP_JWKS = get_idp_jwks()

def verify_id_token(id_token: str, nonce: str) -> Dict:
    """Verify id_token JWT"""
    try:
        # Parse JWT header to get key ID (kid)
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get("kid")
        if not kid:
            raise ValueError("Missing 'kid' in id_token header")

        # Find corresponding key from cached JWKS
        key = next((k for k in IDP_JWKS.get("keys", []) if k["kid"] == kid), None)
        if not key:
            raise ValueError(f"Public key with kid '{kid}' not found in JWKS")

        # Verify JWT
        payload = jwt.decode(
            id_token,
            key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=IdP_BASE_URL
        )
        
        # Verify nonce
        if payload.get("nonce") != nonce:
            raise ValueError("Nonce mismatch")
        
        logger.info(f"ID token verified for user: {payload.get('sub')}")
        return payload
        
    except JWTError as e:
        logger.error(f"JWT verification failed: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid ID token: {e}")
    except Exception as e:
        logger.error(f"ID token verification error: {e}")
        raise HTTPException(status_code=500, detail=f"ID token verification failed: {e}")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, silent_auth_attempted: Optional[str] = None):
    """Client home page"""
    user = await verify_session(request)
    
    # If no local session and silent auth not attempted, try silent authentication (backend processing)
    if not user and not silent_auth_attempted:
        logger.info("No local session, attempting silent authentication.")
        
        # Generate PKCE and state parameters
        state = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        code_verifier = generate_code_verifier()
        
        auth_params = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid email profile",
            "prompt": "none",  # Silent authentication
            "state": state,
            "nonce": nonce,
            "code_challenge": generate_code_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
        
        from urllib.parse import urlencode
        silent_auth_url = f"{IdP_AUTHORIZE_URL}?{urlencode(auth_params)}"
        
        # Create state cookie and redirect to IdP
        state_cookie = create_state_cookie({"state": state, "nonce": nonce, "code_verifier": code_verifier})
        
        response = RedirectResponse(silent_auth_url, status_code=302)
        response.set_cookie(key="state_cookie", value=state_cookie, httponly=True, secure=False, samesite="lax", max_age=300)
        return response
    
    # User is logged in or silent login attempted, display home page
    return templates.TemplateResponse("client_home.html", {
        "request": request, "user": user, "client_name": "Client 2", "client_url": CLIENT_BASE_URL
    })

@app.get("/login")
async def login():
    """Initiate OIDC login flow"""
    # Generate PKCE parameters
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Generate state (CSRF protection) and nonce (replay attack protection)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    
    logger.info(f"Initiating login flow with state: {state[:8]}...")
    
    # Build authorization URL
    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = IdP_AUTHORIZE_URL + "?" + "&".join([f"{k}={v}" for k, v in auth_params.items()])
    
    # Create state cookie
    state_cookie_data = {
        "state": state,
        "nonce": nonce,
        "code_verifier": code_verifier
    }
    state_cookie = create_state_cookie(state_cookie_data)
    
    # Redirect to IdP
    response = RedirectResponse(auth_url, status_code=302)
    response.set_cookie(
        key="state_cookie",
        value=state_cookie,
        httponly=True,
        secure=False,  # Should be set to True in production environment
        samesite="lax",
        max_age=300  # 5 minutes
    )
    
    return response

@app.get("/callback")
async def callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    """Handle OIDC callback"""
    
    if error:
        callback_total.labels(status='failure', error_type='login_required', client='client2').inc()
        logger.warning(
            "Callback failed - login required",
            extra={
                "event": "callback_failure",
                "service": "client2",
                "error_type": "login_required",
                "error": error
            }
        )
        if error == "login_required":
            return RedirectResponse("/?silent_auth_attempted=1")
        raise HTTPException(status_code=400, detail=f"Error from IdP: {error}")

    if not code or not state:
        callback_total.labels(status='failure', error_type='missing_parameters', client='client2').inc()
        logger.error(
            "Callback failed - missing parameters",
            extra={
                "event": "callback_failure",
                "service": "client2",
                "error_type": "missing_parameters"
            }
        )
        raise HTTPException(status_code=400, detail="Missing 'code' or 'state'")
    
    state_cookie_value = request.cookies.get("state_cookie")
    if not state_cookie_value:
        callback_total.labels(status='failure', error_type='missing_state_cookie', client='client2').inc()
        logger.error(
            "Callback failed - missing state cookie",
            extra={
                "event": "callback_failure",
                "service": "client2",
                "error_type": "missing_state_cookie"
            }
        )
        raise HTTPException(status_code=400, detail="Missing state_cookie")
    
    state_data = verify_state_cookie(state_cookie_value)
    if not state_data:
        callback_total.labels(status='failure', error_type='state_cookie_verification_failed', client='client2').inc()
        logger.error(
            "Callback failed - state cookie verification failed",
            extra={
                "event": "callback_failure",
                "service": "client2",
                "error_type": "state_cookie_verification_failed"
            }
        )
        raise HTTPException(status_code=400, detail="Invalid state_cookie")
    
    if state != state_data.get("state"):
        callback_total.labels(status='failure', error_type='state_mismatch', client='client2').inc()
        logger.error(
            "Callback failed - state mismatch",
            extra={
                "event": "callback_failure",
                "service": "client2",
                "error_type": "state_mismatch"
            }
        )
        raise HTTPException(status_code=400, detail="Invalid state")
    
    token_data = {
        "grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID,
        "code_verifier": state_data["code_verifier"]
    }
    
    try:
        # Measure IdP communication latency
        start_time = time.time()
        response = requests.post(IdP_TOKEN_URL, data=token_data, timeout=10)
        duration = time.time() - start_time
        
        response.raise_for_status()
        tokens = response.json()
        
        # Record IdP /token request latency
        idp_request_duration.labels(endpoint='/token', status='success', client='client2').observe(duration)
        logger.info(
            "Token exchange request completed",
            extra={
                "event": "token_exchange_request",
                "service": "client2",
                "endpoint": "/token",
                "duration_ms": round(duration * 1000, 2)
            }
        )
        
        user_info = verify_id_token(tokens["id_token"], state_data["nonce"])
        
        session_data = {
            "user_info": {"sub": user_info["sub"], "email": user_info.get("email"), "name": user_info.get("name")},
            "id_token": tokens["id_token"], "access_token": tokens.get("access_token"),
            "logged_in_at": datetime.now(timezone.utc).isoformat()
        }
        
        session_cookie = create_session_cookie(session_data)
        
        # Record successful callback
        callback_total.labels(status='success', error_type='none', client='client2').inc()
        logger.info(
            "Callback successful",
            extra={
                "event": "callback_success",
                "service": "client2",
                "user_id": user_info.get('sub')
            }
        )
        
        response = RedirectResponse("/", status_code=302)
        response.set_cookie(key="client_session", value=session_cookie, httponly=True, secure=False, samesite="lax", max_age=1800)
        response.delete_cookie("state_cookie")
        
        return response
        
    except requests.RequestException as e:
        callback_total.labels(status='failure', error_type='token_exchange_failed', client='client2').inc()
        logger.error(
            "Token exchange failed",
            extra={
                "event": "callback_failure",
                "service": "client2",
                "error_type": "token_exchange_failed",
                "error": str(e)
            }
        )
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {e}")

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request):
    """Protected user profile page"""
    user = await verify_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    
    return templates.TemplateResponse("client_profile.html", {
        "request": request,
        "user": user,
        "client_name": "Client 2"
    })

@app.get("/logout")
async def logout(request: Request):
    """Execute RP-Initiated Logout"""
    session_cookie = request.cookies.get("client_session")
    id_token_hint = verify_session_cookie(session_cookie).get("id_token") if session_cookie else None

    logout_params = {"post_logout_redirect_uri": CLIENT_BASE_URL}
    if id_token_hint:
        logout_params["id_token_hint"] = id_token_hint
    
    from urllib.parse import urlencode
    idp_logout_url = f"{IdP_LOGOUT_URL}?{urlencode(logout_params)}"

    response = RedirectResponse(idp_logout_url, status_code=302)
    response.delete_cookie("client_session")
    return response

@app.get("/metrics")
async def metrics(request: Request):
    """Prometheus metrics endpoint with access control"""
    # Check if metrics access control is enabled
    restrict_metrics = os.getenv("RESTRICT_METRICS_ACCESS", "false").lower() == "true"

    if restrict_metrics:
        client_ip = request.client.host

        # Get allowed IPs from environment variable, default to localhost for demo
        allowed_ips_env = os.getenv("ALLOWED_METRICS_IPS", "127.0.0.1,localhost,::1")
        allowed_ips = [ip.strip() for ip in allowed_ips_env.split(",")]

        if client_ip not in allowed_ips:
            return Response(
                content="Access denied. Metrics endpoint restricted.",
                status_code=403,
                media_type="text/plain"
            )

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

# Security headers middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Set security headers
    response.headers["Content-Security-Policy"] = "script-src 'self'; object-src 'none';"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Disable caching for pages containing sensitive information
    if request.url.path in ["/callback", "/profile"]:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    
    return response

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
