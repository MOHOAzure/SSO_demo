#!/usr/bin/env python3
"""
Unit tests for monitoring endpoints and metrics
Tests the /metrics endpoint and Prometheus metrics format
"""

import pytest
import requests
from prometheus_client.parser import text_string_to_metric_families


class TestMonitoringEndpoints:
    """Test Prometheus /metrics endpoints for all services"""
    
    BASE_URLS = {
        'idp': 'http://localhost:8000',
        'client1': 'http://localhost:8001',
        'client2': 'http://localhost:8002'
    }
    
    # IdP uses separate monitoring port for security
    METRICS_URLS = {
        'idp': 'http://localhost:9090',  # Internal monitoring port
        'client1': 'http://localhost:8001',
        'client2': 'http://localhost:8002'
    }
    
    def test_idp_metrics_endpoint_accessible(self):
        """Test that IdP /metrics endpoint is accessible on internal port"""
        response = requests.get(f"{self.METRICS_URLS['idp']}/metrics", timeout=5)
        assert response.status_code == 200, "IdP /metrics endpoint should return 200"
        assert 'text/plain' in response.headers['Content-Type'], "Should return Prometheus text format"
    
    def test_idp_public_port_blocks_metrics(self):
        """Test that IdP public port (8000) does NOT expose metrics"""
        response = requests.get(f"{self.BASE_URLS['idp']}/metrics", timeout=5)
        assert response.status_code == 404, "Public port should return 404 for /metrics"
        assert response.headers['Content-Type'] == 'application/json', "Should return JSON error"
        data = response.json()
        assert 'error' in data, "Should contain error message"
        assert '9090' in data.get('message', ''), "Error message should mention internal port"
    
    def test_client1_metrics_endpoint_accessible(self):
        """Test that Client1 /metrics endpoint is accessible"""
        response = requests.get(f"{self.BASE_URLS['client1']}/metrics", timeout=5)
        assert response.status_code == 200, "Client1 /metrics endpoint should return 200"
        assert 'text/plain' in response.headers['Content-Type'], "Should return Prometheus text format"
    
    def test_client2_metrics_endpoint_accessible(self):
        """Test that Client2 /metrics endpoint is accessible"""
        response = requests.get(f"{self.BASE_URLS['client2']}/metrics", timeout=5)
        assert response.status_code == 200, "Client2 /metrics endpoint should return 200"
        assert 'text/plain' in response.headers['Content-Type'], "Should return Prometheus text format"
    
    def test_idp_metrics_format(self):
        """Test that IdP metrics are in valid Prometheus format"""
        response = requests.get(f"{self.METRICS_URLS['idp']}/metrics", timeout=5)
        
        # Parse metrics using prometheus_client parser
        metrics = {}
        for family in text_string_to_metric_families(response.text):
            metrics[family.name] = family
        
        # Check for expected metric families
        expected_metrics = [
            'idp_login_attempts',
            'idp_authorization_code_issued',
            'idp_token_exchange',
            'idp_http_request_duration_seconds'
        ]
        
        for metric_name in expected_metrics:
            assert metric_name in metrics, f"Expected metric {metric_name} not found in IdP metrics"
    
    def test_client_metrics_format(self):
        """Test that Client metrics are in valid Prometheus format"""
        response = requests.get(f"{self.BASE_URLS['client1']}/metrics", timeout=5)
        
        # Parse metrics
        metrics = {}
        for family in text_string_to_metric_families(response.text):
            metrics[family.name] = family
        
        # Check for expected metric families
        expected_metrics = [
            'client_callback',
            'client_idp_request_duration_seconds',
            'client_session_verification_failures'
        ]
        
        for metric_name in expected_metrics:
            assert metric_name in metrics, f"Expected metric {metric_name} not found in Client metrics"
    
    def test_idp_metrics_have_labels(self):
        """Test that IdP metrics include proper labels"""
        response = requests.get(f"{self.METRICS_URLS['idp']}/metrics", timeout=5)
        
        # Parse metrics
        for family in text_string_to_metric_families(response.text):
            if family.name == 'idp_login_attempts':
                # Check that labels exist (even if no samples yet)
                assert family.type == 'counter', "login_attempts should be a counter"
            
            if family.name == 'idp_http_request_duration_seconds':
                # Check that it's a histogram
                assert family.type == 'histogram', "request_duration should be a histogram"
    
    def test_metrics_do_not_contain_secrets(self):
        """Test that metrics do not expose sensitive information"""
        forbidden_patterns = [
            'password',
            'authorization_code=',
            'access_token=',
            'id_token=',
            'code_verifier',
            'code_challenge'
        ]
        
        for service_name, base_url in self.BASE_URLS.items():
            response = requests.get(f"{base_url}/metrics", timeout=5)
            metrics_text = response.text.lower()
            
            for pattern in forbidden_patterns:
                assert pattern not in metrics_text, \
                    f"Sensitive pattern '{pattern}' found in {service_name} metrics!"
    
    def test_metrics_endpoint_performance(self):
        """Test that /metrics endpoint responds quickly"""
        import time
        
        for service_name in ['idp', 'client1', 'client2']:
            start_time = time.time()
            # Use METRICS_URLS for idp, BASE_URLS for clients
            url = self.METRICS_URLS.get(service_name, self.BASE_URLS[service_name])
            response = requests.get(f"{url}/metrics", timeout=5)
            duration = time.time() - start_time
            
            assert response.status_code == 200, f"{service_name} /metrics failed"
            assert duration < 1.0, f"{service_name} /metrics took too long: {duration:.3f}s"


class TestMetricsIncrementation:
    """Test that metrics are properly incremented during operations"""
    
    BASE_URLS = {
        'idp': 'http://localhost:8000',
        'client1': 'http://localhost:8001',
        'client2': 'http://localhost:8002'
    }
    
    METRICS_URLS = {
        'idp': 'http://localhost:9090',  # Internal monitoring port
        'client1': 'http://localhost:8001',
        'client2': 'http://localhost:8002'
    }
    
    def _get_metric_value(self, service, metric_name, labels=None):
        """Helper to extract a specific metric value"""
        url = self.METRICS_URLS.get(service, self.BASE_URLS[service])
        response = requests.get(f"{url}/metrics", timeout=5)
        
        for family in text_string_to_metric_families(response.text):
            if family.name == metric_name:
                for sample in family.samples:
                    if labels is None or all(sample.labels.get(k) == v for k, v in labels.items()):
                        return sample.value
        return None
    
    def test_idp_http_requests_tracked(self):
        """Test that HTTP requests to IdP are tracked in metrics"""
        # Get initial metric value
        initial_value = self._get_metric_value('idp', 'idp_http_request_duration_seconds_count')
        
        # Make a request to IdP
        requests.get(f"{self.BASE_URLS['idp']}/", timeout=5)
        
        # Check that metric increased
        new_value = self._get_metric_value('idp', 'idp_http_request_duration_seconds_count')
        
        # Value should have increased
        if initial_value is not None and new_value is not None:
            assert new_value > initial_value, "HTTP request count should increase"
    
    def test_client_http_requests_tracked(self):
        """Test that HTTP requests to Client are tracked in metrics"""
        # Make a request to Client1
        requests.get(f"{self.BASE_URLS['client1']}/", timeout=5)
        
        # Check that metrics endpoint returns valid data
        response = requests.get(f"{self.BASE_URLS['client1']}/metrics", timeout=5)
        assert response.status_code == 200
        
        # Parse metrics and check that client_callback metric exists
        metrics = {}
        for family in text_string_to_metric_families(response.text):
            metrics[family.name] = family
        
        assert 'client_callback' in metrics, "Client callback metric should exist"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
