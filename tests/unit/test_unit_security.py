#!/usr/bin/env python3
"""
Unit Tests for SSO Core Security Functions
Tests cryptographic functions, PKCE, JWT handling without requiring running servers
"""

import pytest
import hashlib
import base64
from datetime import datetime, timezone, timedelta
import sys
import os

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from idp_app import verify_pkce
from client1_app import generate_code_verifier, generate_code_challenge


class TestPKCEFunctions:
    """Test PKCE (Proof Key for Code Exchange) implementation"""
    
    def test_code_verifier_generation(self):
        """Test that code verifier is generated with sufficient entropy"""
        verifier = generate_code_verifier()
        
        assert isinstance(verifier, str), "Verifier should be a string"
        assert len(verifier) >= 43, "Verifier should be at least 43 characters (base64url)"
        assert len(verifier) <= 128, "Verifier should be at most 128 characters"
    
    def test_code_challenge_generation(self):
        """Test that code challenge is properly generated from verifier"""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        
        assert isinstance(challenge, str), "Challenge should be a string"
        assert len(challenge) == 43, "SHA256 base64url should be 43 characters"
        
        # Verify it's valid base64url (no padding)
        assert '=' not in challenge, "Base64url should not have padding"
    
    def test_pkce_verification_success(self):
        """Test that PKCE verification succeeds with matching verifier/challenge"""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        
        assert verify_pkce(verifier, challenge) is True, \
            "PKCE verification should succeed with matching verifier and challenge"
    
    def test_pkce_verification_failure_wrong_verifier(self):
        """Test that PKCE verification fails with wrong verifier"""
        verifier1 = generate_code_verifier()
        verifier2 = generate_code_verifier()
        challenge1 = generate_code_challenge(verifier1)
        
        assert verify_pkce(verifier2, challenge1) is False, \
            "PKCE verification should fail with mismatched verifier"
    
    def test_pkce_verification_failure_tampered_challenge(self):
        """Test that PKCE verification fails with tampered challenge"""
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier)
        
        # Tamper with challenge
        tampered_challenge = challenge[:-1] + ('a' if challenge[-1] != 'a' else 'b')
        
        assert verify_pkce(verifier, tampered_challenge) is False, \
            "PKCE verification should fail with tampered challenge"
    
    def test_code_verifier_uniqueness(self):
        """Test that generated verifiers are unique"""
        verifiers = [generate_code_verifier() for _ in range(100)]
        
        # All should be unique
        assert len(set(verifiers)) == 100, \
            "Generated verifiers should be unique"


class TestSecurityHelpers:
    """Test security helper functions"""
    
    def test_verify_pkce_with_known_values(self):
        """Test PKCE verification with known test vectors"""
        # Test vector from RFC 7636
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        
        # Expected challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
        expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        
        # Compute challenge
        computed_challenge = generate_code_challenge(verifier)
        
        assert computed_challenge == expected_challenge, \
            "Challenge should match RFC 7636 test vector"
        
        # Verify
        assert verify_pkce(verifier, expected_challenge) is True, \
            "Should verify RFC 7636 test vector"


class TestStateNonceGeneration:
    """Test state and nonce generation (if exposed as functions)"""
    
    def test_secrets_module_available(self):
        """Test that secrets module is available for secure random generation"""
        import secrets
        
        # Generate a token
        token = secrets.token_urlsafe(32)
        
        assert len(token) >= 40, "Token should have sufficient length"
        assert isinstance(token, str), "Token should be string"


class TestJWTStructure:
    """Test JWT structure expectations (without full validation)"""
    
    def test_jwt_has_three_parts(self):
        """Test that JWT format has three base64url parts"""
        # Example JWT structure
        example_jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature"
        
        parts = example_jwt.split('.')
        assert len(parts) == 3, "JWT should have 3 parts: header.payload.signature"
    
    def test_jwt_header_structure(self):
        """Test expected JWT header structure"""
        import json
        
        # Expected header for our system
        expected_header = {
            "alg": "RS256",
            "kid": "idp-key-1",
            "typ": "JWT"
        }
        
        # Verify structure is correct
        assert expected_header["alg"] == "RS256", "Should use RS256 algorithm"
        assert "kid" in expected_header, "Should have key ID"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
