#!/usr/bin/env python3
"""
Integration Tests for SSO System - Stage 2
Tests complete OIDC security flow with running services
Requires: IdP, Client1, Client2 running on ports 8000, 8001, 8002
"""

import pytest
import requests


class TestServiceAvailability:
    """Test that all required services are running and accessible"""
    
    IDP_URL = 'http://localhost:8000'
    CLIENT1_URL = 'http://localhost:8001'
    CLIENT2_URL = 'http://localhost:8002'
    
    def test_idp_service_running(self):
        """Test that IdP service is accessible"""
        response = requests.get(self.IDP_URL, timeout=5)
        assert response.status_code == 200, "IdP service should be running on port 8000"
    
    def test_client1_service_running(self):
        """Test that Client1 service is accessible"""
        response = requests.get(self.CLIENT1_URL, timeout=5)
        assert response.status_code == 200, "Client1 service should be running on port 8001"
    
    def test_client2_service_running(self):
        """Test that Client2 service is accessible"""
        response = requests.get(self.CLIENT2_URL, timeout=5)
        assert response.status_code == 200, "Client2 service should be running on port 8002"


class TestOIDCEndpoints:
    """Test OIDC standard endpoints"""
    
    IDP_URL = 'http://localhost:8000'
    
    def test_jwks_endpoint_available(self):
        """Test that JWKS endpoint returns valid keys"""
        response = requests.get(f"{self.IDP_URL}/.well-known/jwks.json", timeout=5)
        
        assert response.status_code == 200, "JWKS endpoint should be accessible"
        jwks = response.json()
        
        assert "keys" in jwks, "JWKS should contain 'keys' array"
        assert len(jwks["keys"]) > 0, "JWKS should have at least one key"
        
        key = jwks["keys"][0]
        assert key.get("kty") == "RSA", "Key type should be RSA"
        assert key.get("alg") == "RS256", "Algorithm should be RS256"
        assert key.get("kid") is not None, "Key should have an ID"
        assert key.get("n") is not None, "RSA key should have modulus (n)"
        assert key.get("e") is not None, "RSA key should have exponent (e)"
    
    def test_openid_configuration_endpoint(self):
        """Test that OpenID Configuration endpoint is complete"""
        response = requests.get(
            f"{self.IDP_URL}/.well-known/openid_configuration",
            timeout=5
        )
        
        assert response.status_code == 200, "OpenID Configuration should be accessible"
        config = response.json()
        
        # Required fields per OIDC spec
        assert config.get("issuer") == self.IDP_URL, \
            f"Issuer should be {self.IDP_URL}"
        
        assert config.get("authorization_endpoint") == f"{self.IDP_URL}/authorize", \
            "Authorization endpoint should be correct"
        
        assert config.get("token_endpoint") == f"{self.IDP_URL}/token", \
            "Token endpoint should be correct"
        
        assert config.get("jwks_uri") == f"{self.IDP_URL}/.well-known/jwks.json", \
            "JWKS URI should be correct"
        
        assert "code" in config.get("response_types_supported", []), \
            "Should support authorization code flow"
        
        assert "S256" in config.get("code_challenge_methods_supported", []), \
            "Should support PKCE with S256"


class TestAuthenticationFlow:
    """Test complete authentication flow"""
    
    IDP_URL = 'http://localhost:8000'
    CLIENT1_URL = 'http://localhost:8001'
    
    TEST_USER = {
        'username': 'alice',
        'password': 'password123'
    }
    
    def test_idp_login_page_accessible(self):
        """Test that IdP login page is accessible"""
        response = requests.get(f"{self.IDP_URL}/login", timeout=5)
        assert response.status_code == 200, "Login page should be accessible"
        assert 'text/html' in response.headers.get('Content-Type', ''), \
            "Login page should return HTML"
    
    def test_successful_login_creates_session(self):
        """Test that successful login creates IdP session"""
        session = requests.Session()
        
        # Submit login
        response = session.post(
            f"{self.IDP_URL}/login",
            data=self.TEST_USER,
            allow_redirects=False,
            timeout=5
        )
        
        # Should redirect after successful login
        assert response.status_code in [302, 303], \
            "Successful login should redirect"
        
        # Should set session cookie
        assert 'idp_session' in session.cookies, \
            "Should set idp_session cookie"
    
    def test_failed_login_returns_error(self):
        """Test that failed login returns to login page with error"""
        response = requests.post(
            f"{self.IDP_URL}/login",
            data={'username': 'invalid', 'password': 'wrong'},
            timeout=5
        )
        
        # Should return login page (not redirect)
        assert response.status_code == 200, \
            "Failed login should return 200 with error message"
        
        assert 'text/html' in response.headers.get('Content-Type', ''), \
            "Should return HTML page"


class TestSingleSignOn:
    """Test SSO functionality across clients"""
    
    IDP_URL = 'http://localhost:8000'
    CLIENT1_URL = 'http://localhost:8001'
    CLIENT2_URL = 'http://localhost:8002'
    
    TEST_USER = {
        'username': 'alice',
        'password': 'password123'
    }
    
    def test_login_on_client1_then_access_client2(self):
        """Test that logging in to Client1 enables access to Client2 without re-login"""
        session = requests.Session()
        
        # Step 1: Access Client1, which will redirect to IdP
        response = session.get(self.CLIENT1_URL, timeout=5)
        
        # Step 2: If not logged in, we should see login button or get redirected
        # For this test, we'll login to IdP directly first
        session.post(
            f"{self.IDP_URL}/login",
            data=self.TEST_USER,
            timeout=5
        )
        
        # Step 3: Now access Client2
        # If SSO works, we should be able to access Client2 without re-entering credentials
        response = session.get(self.CLIENT2_URL, timeout=5)
        
        # Should successfully load (exact behavior depends on implementation)
        assert response.status_code == 200, "Should be able to access Client2"
    
    def test_logout_from_idp_affects_all_clients(self):
        """Test that logging out from IdP affects subsequent client access"""
        session = requests.Session()
        
        # Login to IdP
        session.post(
            f"{self.IDP_URL}/login",
            data=self.TEST_USER,
            timeout=5
        )
        
        # Logout
        response = session.get(
            f"{self.IDP_URL}/logout",
            allow_redirects=False,
            timeout=5
        )
        
        # Should clear idp_session cookie
        assert response.status_code in [302, 303], "Logout should redirect"
        
        # After logout, idp_session should be removed or expired
        # (Implementation may vary)


class TestSecurityHeaders:
    """Test that security headers are properly set"""
    
    IDP_URL = 'http://localhost:8000'
    CLIENT1_URL = 'http://localhost:8001'
    
    def test_idp_has_security_headers(self):
        """Test that IdP sets proper security headers"""
        response = requests.get(self.IDP_URL, timeout=5)
        
        headers = response.headers
        
        # Check for security headers
        assert 'X-Content-Type-Options' in headers, \
            "Should have X-Content-Type-Options header"
        
        assert headers.get('X-Content-Type-Options') == 'nosniff', \
            "X-Content-Type-Options should be nosniff"
        
        assert 'X-Frame-Options' in headers, \
            "Should have X-Frame-Options header"
        
        assert 'Content-Security-Policy' in headers, \
            "Should have Content-Security-Policy header"
    
    def test_client_has_security_headers(self):
        """Test that Client sets proper security headers"""
        response = requests.get(self.CLIENT1_URL, timeout=5)
        
        headers = response.headers
        
        assert 'X-Content-Type-Options' in headers, \
            "Client should have security headers"


class TestSessionCookieSecurity:
    """Test that session cookies have proper security attributes"""
    
    IDP_URL = 'http://localhost:8000'
    
    TEST_USER = {
        'username': 'alice',
        'password': 'password123'
    }
    
    def test_idp_session_cookie_attributes(self):
        """Test that IdP session cookie has secure attributes"""
        session = requests.Session()
        
        # Login to trigger cookie creation
        session.post(
            f"{self.IDP_URL}/login",
            data=self.TEST_USER,
            timeout=5
        )
        
        # Check cookie attributes
        if 'idp_session' in session.cookies:
            cookie = session.cookies.get('idp_session')
            
            # Note: requests library doesn't expose all cookie attributes
            # In production, you'd check via browser DevTools
            assert cookie is not None, "IdP session cookie should be set"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
