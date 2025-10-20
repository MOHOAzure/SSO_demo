#!/usr/bin/env python3
"""
IdP (Identity Provider) Server
Implements complete OIDC security mechanisms with monitoring and observability:
- PKCE verification
- state parameter passthrough
- nonce handling
- Standard JWT (id_token) generation and signing
- JWKS endpoint
- Secure session cookies
- Prometheus metrics monitoring
- Structured JSON logging
"""

import os
import hashlib
import secrets
import base64
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
import logging
from contextlib import asynccontextmanager
from urllib.parse import unquote

import uvicorn
from fastapi import FastAPI, Request, Response, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from jose import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
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
logger = logging.getLogger("IdP")
logger.addHandler(logHandler)

# Prometheus Metrics definitions
logger.setLevel(logging.INFO)

# Prometheus Metrics definitions
login_attempts = Counter(
    'idp_login_attempts_total',
    'Total number of login attempts',
    ['status', 'username']
)

auth_code_issued = Counter(
    'idp_authorization_code_issued_total',
    'Total number of authorization codes issued',
    ['client_id']
)

token_exchange = Counter(
    'idp_token_exchange_total',
    'Total number of token exchange attempts',
    ['client_id', 'status', 'error_type']
)

http_request_duration = Histogram(
    'idp_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint', 'status_code'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    load_or_generate_keys()
    logger.info("IdP server started", extra={"event": "startup", "service": "idp"})
    yield
    # Shutdown
    logger.info("IdP server shutdown", extra={"event": "shutdown", "service": "idp"})

# Prometheus middleware
class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip monitoring the /metrics endpoint itself
        if request.url.path == "/metrics":
            return await call_next(request)
        
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        # Record request latency
        http_request_duration.labels(
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code
        ).observe(duration)
        
        return response

app = FastAPI(title="IdP Server - Stage 3 (Monitoring)", lifespan=lifespan)
app.add_middleware(PrometheusMiddleware)
templates = Jinja2Templates(directory="templates")

# Generate or load RSA key pair
PRIVATE_KEY_PATH = "idp_private_key.pem"
PUBLIC_KEY_PATH = "idp_public_key.pem"

# Global key variables
private_key = None
public_key = None
JWK_KEY = None

def load_or_generate_keys():
    global private_key, public_key, JWK_KEY
    if not os.path.exists(PRIVATE_KEY_PATH):
        # Generate new key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Save private key
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        logger.info("Generated new RSA key pair")
    else:
        # Load existing key pair
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        
        logger.info("Loaded existing RSA key pair")

    # Convert to JWK format for JWKS endpoint
    JWK_KEY = rsa_key_to_jwk(public_key)

def rsa_key_to_jwk(pk, kid: str = "idp-key-1"):
    """Convert RSA public key to JWK format"""
    numbers = pk.public_numbers()
    
    def int_to_base64url(val):
        """Convert integer to base64url encoding"""
        byte_length = (val.bit_length() + 7) // 8
        val_bytes = val.to_bytes(byte_length, 'big')
        return base64.urlsafe_b64encode(val_bytes).decode('ascii').rstrip('=')
    
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": int_to_base64url(numbers.n),
        "e": int_to_base64url(numbers.e)
    }

# Configuration
IdP_ISSUER = "http://localhost:8000"
JWT_ALGORITHM = "RS256"
JWT_EXPIRATION_MINUTES = 30

# Simulated user database
USERS_DB = {
    "alice": {
        "password": "password123",
        "user_id": "user_alice_001",
        "email": "alice@example.com",
        "name": "Alice Smith"
    },
    "bob": {
        "password": "password456", 
        "user_id": "user_bob_002",
        "email": "bob@example.com",
        "name": "Bob Johnson"
    }
}

# Authorization code storage (production should use Redis, etc.)
authorization_codes: Dict[str, Dict] = {}

# Registered clients
REGISTERED_CLIENTS = {
    "client1": {
        "redirect_uris": ["http://localhost:8001/callback"],
        "post_logout_redirect_uris": ["http://localhost:8001"]
    },
    "client2": {
        "redirect_uris": ["http://localhost:8002/callback"],
        "post_logout_redirect_uris": ["http://localhost:8002"]
    }
}


class AuthorizeRequest(BaseModel):
    response_type: str
    client_id: str
    redirect_uri: str
    scope: str
    state: str
    nonce: Optional[str] = None
    code_challenge: str
    code_challenge_method: str

class TokenRequest(BaseModel):
    grant_type: str
    code: str
    client_id: str
    code_verifier: str

def create_session_cookie(data: Dict, max_age: int = 1800) -> str:
    """Create secure signed JWT session cookie"""
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "iss": IdP_ISSUER,
        "exp": now + timedelta(seconds=max_age),
        "iat": now
    }
    
    # Sign with private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return jwt.encode(payload, private_key_pem, algorithm=JWT_ALGORITHM)

def verify_session_cookie(cookie_value: str) -> Optional[Dict]:
    """Verify secure signed JWT session cookie"""
    try:
        # Verify with public key
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        payload = jwt.decode(
            cookie_value, 
            public_key_pem, 
            algorithms=[JWT_ALGORITHM],
            issuer=IdP_ISSUER
        )
        return payload
    except Exception as e:
        logger.warning(f"Cookie verification failed: {e}")
        return None

def get_current_user(request: Request) -> Optional[Dict]:
    """Get current user from secure cookie"""
    idp_session = request.cookies.get("idp_session")
    if not idp_session:
        return None
    
    session_data = verify_session_cookie(idp_session)
    if not session_data:
        return None
    
    user_id = session_data.get("user_id")
    if not user_id:
        return None
    
    # Find user
    for username, user_info in USERS_DB.items():
        if user_info["user_id"] == user_id:
            return {**user_info, "username": username}
    
    return None

def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE (Proof Key for Code Exchange)"""
    # Calculate SHA256 hash of code_verifier
    verifier_hash = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    # Convert to base64url format
    computed_challenge = base64.urlsafe_b64encode(verifier_hash).decode('utf-8').rstrip('=')
    return computed_challenge == code_challenge

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """IdP home page"""
    user = get_current_user(request)
    return templates.TemplateResponse("idp_home.html", {
        "request": request,
        "user": user,
        "idp_url": IdP_ISSUER
    })

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, redirect_uri: Optional[str] = None):
    """Display login page"""
    # Check if already logged in
    user = get_current_user(request)
    if user:
        if redirect_uri:
            return RedirectResponse(redirect_uri, status_code=302)
        return RedirectResponse("/", status_code=302)
    
    return templates.TemplateResponse("idp_login.html", {
        "request": request,
        "idp_url": IdP_ISSUER,
        "redirect_uri": redirect_uri or "/"
    })

@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    redirect_uri: str = Form("/")
):
    """Process login form submission"""
    remote_ip = request.client.host if request.client else "unknown"
    
    user = USERS_DB.get(username)
    if not user or user["password"] != password:
        # Record failed metric
        login_attempts.labels(status='failure', username=username).inc()
        
        # Record failed JSON log
        logger.warning(
            "Login failed - invalid credentials",
            extra={
                "event": "login_failure",
                "service": "idp",
                "username": username,
                "remote_ip": remote_ip,
                "failure_reason": "invalid_credentials"
            }
        )
        
        return templates.TemplateResponse("idp_login.html", {
            "request": request,
            "error": "Invalid username or password",
            "idp_url": IdP_ISSUER,
            "redirect_uri": redirect_uri
        })
    
    # Record successful metric
    login_attempts.labels(status='success', username=username).inc()
    
    session_data = {
        "user_id": user["user_id"],
        "username": username
    }
    
    cookie_value = create_session_cookie(session_data)
    
    # URL decode redirect_uri (unquote is idempotent, can be safely called always)
    decoded_redirect_uri = unquote(redirect_uri)
    
    # Record successful JSON log
    logger.info(
        "User logged in successfully",
        extra={
            "event": "login_success",
            "service": "idp",
            "user_id": user["user_id"],
            "username": username,
            "remote_ip": remote_ip,
            "redirect_uri": decoded_redirect_uri
        }
    )
    
    response = RedirectResponse(decoded_redirect_uri, status_code=302)
    response.set_cookie(
        key="idp_session",
        value=cookie_value,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=1800
    )
    
    logger.info(f"Login successful for user: {username}")
    return response

@app.get("/authorize")
async def authorize_endpoint(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    nonce: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    prompt: Optional[str] = None
):
    """OIDC authorization endpoint"""
    logger.info(f"Authorization request from client: {client_id}")
    
    # Validate required parameters
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")
    
    if client_id not in REGISTERED_CLIENTS:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    if redirect_uri not in REGISTERED_CLIENTS[client_id]["redirect_uris"]:
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    # Validate PKCE parameters
    if not code_challenge or code_challenge_method != "S256":
        raise HTTPException(status_code=400, detail="PKCE required: code_challenge and code_challenge_method=S256")
    
    # Check if user is already logged in
    user = get_current_user(request)
    if not user:
        # If silent auth request and user not logged in, return error directly
        if prompt == "none":
            error_url = f"{redirect_uri}?error=login_required&state={state}"
            return RedirectResponse(error_url, status_code=302)
        
        # Redirect to login page, and return here after login
        from urllib.parse import quote_plus
        full_request_path = quote_plus(str(request.url))
        login_url = f"/login?redirect_uri={full_request_path}"
        return RedirectResponse(login_url, status_code=302)
    
    # User is logged in, generate authorization code
    auth_code = secrets.token_urlsafe(32)
    
    # Store authorization code related information
    authorization_codes[auth_code] = {
        "user_id": user["user_id"],
        "client_id": client_id,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "scope": scope,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),  # Authorization code expires in 10 minutes
        "used": False
    }
    
    # Record authorization code issued metric (dynamic client_id)
    auth_code_issued.labels(client_id=client_id).inc()
    
    # Record authorization code issued JSON log
    logger.info(
        "Authorization code issued",
        extra={
            "event": "authorization_code_issued",
            "service": "idp",
            "client_id": client_id,
            "user_id": user["user_id"],
            "prompt": prompt or "normal"
        }
    )
    
    # Build callback URL
    callback_url = f"{redirect_uri}?code={auth_code}&state={state}"
    return RedirectResponse(callback_url, status_code=302)

@app.post("/token")
async def token_endpoint(
    grant_type: str = Form(...),
    code: str = Form(...),
    client_id: str = Form(...),
    code_verifier: str = Form(...)
):
    """OIDC token endpoint"""
    logger.info(f"Token request from client: {client_id}")
    
    # Validate grant_type
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Unsupported grant_type")
    
    # Validate authorization code
    if code not in authorization_codes:
        token_exchange.labels(client_id=client_id, status='failure', error_type='invalid_code').inc()
        logger.warning(
            "Token exchange failed - invalid code",
            extra={
                "event": "token_exchange_failure",
                "service": "idp",
                "client_id": client_id,
                "error_type": "invalid_code"
            }
        )
        raise HTTPException(status_code=400, detail="Invalid authorization code")
    
    code_data = authorization_codes[code]
    
    # Check if authorization code is already used or expired
    if code_data["used"]:
        token_exchange.labels(client_id=client_id, status='failure', error_type='code_already_used').inc()
        logger.warning(
            "Token exchange failed - code already used",
            extra={
                "event": "token_exchange_failure",
                "service": "idp",
                "client_id": client_id,
                "error_type": "code_already_used"
            }
        )
        raise HTTPException(status_code=400, detail="Authorization code already used")
    
    if datetime.now(timezone.utc) > code_data["expires_at"]:
        token_exchange.labels(client_id=client_id, status='failure', error_type='code_expired').inc()
        logger.warning(
            "Token exchange failed - code expired",
            extra={
                "event": "token_exchange_failure",
                "service": "idp",
                "client_id": client_id,
                "error_type": "code_expired"
            }
        )
        raise HTTPException(status_code=400, detail="Authorization code expired")
    
    # Validate client
    if code_data["client_id"] != client_id:
        token_exchange.labels(client_id=client_id, status='failure', error_type='client_id_mismatch').inc()
        logger.warning(
            "Token exchange failed - client ID mismatch",
            extra={
                "event": "token_exchange_failure",
                "service": "idp",
                "client_id": client_id,
                "error_type": "client_id_mismatch",
                "expected_client_id": code_data['client_id']
            }
        )
        raise HTTPException(status_code=400, detail="Client ID mismatch")
    
    # Validate PKCE
    if not verify_pkce(code_verifier, code_data["code_challenge"]):
        token_exchange.labels(client_id=client_id, status='failure', error_type='pkce_failed').inc()
        logger.warning(
            "Token exchange failed - PKCE verification failed",
            extra={
                "event": "token_exchange_failure",
                "service": "idp",
                "client_id": client_id,
                "error_type": "pkce_failed"
            }
        )
        raise HTTPException(status_code=400, detail="PKCE verification failed")
    
    # Mark authorization code as used
    code_data["used"] = True
    
    # Find user information
    user_info = None
    for username, user_data in USERS_DB.items():
        if user_data["user_id"] == code_data["user_id"]:
            user_info = {**user_data, "username": username}
            break
    
    if not user_info:
        raise HTTPException(status_code=500, detail="User not found")
    
    # Generate id_token (JWT)
    now = datetime.now(timezone.utc)
    id_token_payload = {
        "iss": IdP_ISSUER,  # Issuer
        "sub": user_info["user_id"],  # Subject (user ID)
        "aud": client_id,  # Audience (client ID)
        "exp": now + timedelta(minutes=JWT_EXPIRATION_MINUTES),  # Expiration time
        "iat": now,  # Issued at time
        "email": user_info["email"],
        "name": user_info["name"]
    }
    
    # Include nonce (if provided)
    if code_data["nonce"]:
        id_token_payload["nonce"] = code_data["nonce"]
    
    # Sign JWT with private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    id_token = jwt.encode(
        id_token_payload,
        private_key_pem,
        algorithm=JWT_ALGORITHM,
        headers={"kid": JWK_KEY["kid"]}
    )
    
    # Generate access_token (simplified implementation, also using JWT)
    access_token_payload = {
        "iss": IdP_ISSUER,
        "sub": user_info["user_id"],
        "aud": client_id,
        "exp": now + timedelta(minutes=60),  # access_token has longer validity period
        "iat": now,
        "scope": code_data["scope"]
    }
    
    access_token = jwt.encode(
        access_token_payload,
        private_key_pem,
        algorithm=JWT_ALGORITHM,
        headers={"kid": JWK_KEY["kid"]}
    )
    
    # Record successful metric
    token_exchange.labels(client_id=client_id, status='success', error_type='none').inc()
    
    # Record successful JSON log
    logger.info(
        "Token exchange successful",
        extra={
            "event": "token_exchange_success",
            "service": "idp",
            "client_id": client_id,
            "user_id": user_info["user_id"]
        }
    )
    
    # Clean up used authorization code
    del authorization_codes[code]
    
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,  # 1 hour
        "id_token": id_token
    }

@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """JWKS (JSON Web Key Set) endpoint, publishes public keys for JWT verification"""
    return {
        "keys": [JWK_KEY]
    }

@app.get("/.well-known/openid_configuration")
async def openid_configuration():
    """OpenID Connect Discovery endpoint"""
    return {
        "issuer": IdP_ISSUER,
        "authorization_endpoint": f"{IdP_ISSUER}/authorize",
        "token_endpoint": f"{IdP_ISSUER}/token",
        "jwks_uri": f"{IdP_ISSUER}/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
        "end_session_endpoint": f"{IdP_ISSUER}/logout"
    }

@app.get("/logout")
async def logout_page(
    request: Request,
    id_token_hint: Optional[str] = None,
    post_logout_redirect_uri: Optional[str] = None
):
    """RP-Initiated Logout endpoint"""
    user = get_current_user(request)
    client_id_from_token = None
    
    if user:
        # Record logout JSON log
        logger.info(
            "User logout",
            extra={
                "event": "logout",
                "service": "idp",
                "user_id": user["user_id"],
                "username": user.get("username", "unknown")
            }
        )

    final_redirect_uri = "/"
    if id_token_hint and post_logout_redirect_uri:
        try:
            # Normalize URL (remove trailing slash to ensure matching)
            normalized_post_logout_uri = post_logout_redirect_uri.rstrip('/')
            
            unverified_claims = jwt.get_unverified_claims(id_token_hint)
            client_id_from_token = unverified_claims.get("aud")
            if client_id_from_token in REGISTERED_CLIENTS:
                # Also normalize registered URIs
                registered_uris = [uri.rstrip('/') for uri in REGISTERED_CLIENTS[client_id_from_token]["post_logout_redirect_uris"]]
                if normalized_post_logout_uri in registered_uris:
                    final_redirect_uri = normalized_post_logout_uri
                    logger.info(
                        "Logout redirect to client",
                        extra={
                            "event": "logout",
                            "service": "idp",
                            "client_id": client_id_from_token,
                            "redirect_uri": final_redirect_uri
                        }
                    )
                else:
                    logger.warning(f"post_logout_redirect_uri not registered: {normalized_post_logout_uri}")
            else:
                logger.warning(f"Client not found: {client_id_from_token}")
        except Exception as e:
            logger.warning(f"Invalid id_token_hint: {e}")

    response = RedirectResponse(final_redirect_uri, status_code=302)
    response.delete_cookie("idp_session")
    return response

# =============================================================================
# MONITORING ENDPOINT - Production Best Practice
# =============================================================================
# IMPORTANT: In production, /metrics should NEVER be exposed on the public port.
# 
# Best practices for securing Prometheus metrics:
# 1. ✅ Separate port binding (implemented below)
#    - Public services: 0.0.0.0:8000
#    - Metrics endpoint: 127.0.0.1:9090 (localhost only)
#
# 2. ✅ Network isolation
#    - Use firewall rules to restrict access to metrics port
#    - In Kubernetes: use NetworkPolicy to limit Pod-to-Pod communication
#    - In Docker: use internal networks
#
# 3. ✅ Infrastructure-level security
#    - Prometheus scrapes from internal network only
#    - No public internet exposure of metrics
#
# 4. Additional options for production:
#    - mTLS authentication between Prometheus and targets
#    - Reverse proxy (nginx/Envoy) with IP allowlists
#    - VPC/Security Groups in cloud environments
#
# This implementation uses dual-port architecture for demonstration.
# =============================================================================

@app.get("/metrics")
async def metrics_redirect():
    """
    Metrics endpoint on public port - redirects with instructions.
    
    For security reasons, metrics are served on a separate internal port.
    This prevents accidental exposure of monitoring data to the public internet.
    """
    return JSONResponse(
        status_code=404,
        content={
            "error": "Metrics not available on public port",
            "message": "Metrics are served on internal port 9090 (localhost only) for security",
            "production_recommendation": "Configure Prometheus to scrape from internal network",
            "local_access": "curl http://localhost:9090/metrics"
        }
    )

# Separate FastAPI app for metrics (internal monitoring port)
# IMPORTANT: Uses the same Prometheus registry as main app to share metrics
metrics_app = FastAPI(title="IdP Metrics - Internal Only")

@metrics_app.get("/metrics")
async def internal_metrics():
    """
    Internal metrics endpoint - only accessible from localhost.
    
    This endpoint exposes the same metrics as the main app since they
    share the same Prometheus registry (same process, different port).
    
    This endpoint should be scraped by Prometheus from within the same
    network/infrastructure, never exposed to the public internet.
    """
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )

@metrics_app.get("/health")
async def metrics_health():
    """Health check for monitoring port"""
    return {
        "status": "healthy",
        "service": "idp-metrics",
        "note": "This port is for internal monitoring only"
    }

# Security headers middleware
@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Filter Chrome DevTools requests to avoid log noise
    if request.url.path == "/.well-known/appspecific/com.chrome.devtools.json":
        return JSONResponse(status_code=404, content={"error": "Not found"})
    
    response = await call_next(request)
    
    # Set security headers
    response.headers["Content-Security-Policy"] = "script-src 'self'; object-src 'none';"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Disable caching for pages containing sensitive information
    if request.url.path in ["/authorize", "/login"]:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
    
    return response

if __name__ == "__main__":
    import asyncio
    import threading
    
    def run_metrics_server():
        """Run metrics server in background thread"""
        logger.info(
            "Starting metrics endpoint",
            extra={
                "event": "startup",
                "service": "idp-metrics",
                "host": "127.0.0.1",
                "port": 9090,
                "note": "Internal monitoring only - not exposed to public internet"
            }
        )
        uvicorn.run(metrics_app, host="127.0.0.1", port=9090, log_level="warning")
    
    # Start metrics server in background thread
    metrics_thread = threading.Thread(target=run_metrics_server, daemon=True, name="IdP-Metrics")
    metrics_thread.start()
    
    # Give metrics server time to start
    import time
    time.sleep(1)
    
    print("=" * 80)
    print("🚀 IdP Server Started with Production-Grade Monitoring Architecture")
    print("=" * 80)
    print(f"📍 Main Application:    http://0.0.0.0:8000 (Public)")
    print(f"📊 Metrics Endpoint:    http://127.0.0.1:9090/metrics (Internal Only)")
    print(f"💚 Health Check:        http://127.0.0.1:9090/health")
    print("=" * 80)
    print("🔒 Security Note:")
    print("   - Main app (8000) is accessible from anywhere")
    print("   - Metrics (9090) only accessible from localhost")
    print("   - Metrics from BOTH ports share the same data (same process)")
    print("   - Configure Prometheus to scrape from internal network (port 9090)")
    print("=" * 80)
    
    # Run main app in main thread
    logger.info(
        "Starting IdP main application",
        extra={
            "event": "startup",
            "service": "idp",
            "host": "0.0.0.0",
            "port": 8000,
            "note": "Public OIDC endpoints"
        }
    )
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")

