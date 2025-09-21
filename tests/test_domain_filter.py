"""
Tests for domain filtering functionality.
"""

import json
import os
import tempfile
import pytest

import requests
from requests.domain_filter import (
    _extract_domain_from_url,
    _get_allowed_domains_file_path,
    _load_allowed_domains,
    is_domain_allowed,
    validate_domain_or_raise
)
from requests.exceptions import DomainFilterError


class TestDomainFilter:
    """Test domain filtering functionality."""

    def test_extract_domain_from_url(self):
        """Test domain extraction from various URL formats."""
        assert _extract_domain_from_url("https://example.com/path") == "example.com"
        assert _extract_domain_from_url("http://www.example.com:8080/path") == "www.example.com"
        assert _extract_domain_from_url("https://localhost:3000") == "localhost"
        assert _extract_domain_from_url("http://127.0.0.1:8000") == "127.0.0.1"
        assert _extract_domain_from_url("ftp://files.example.com") == "files.example.com"
        assert _extract_domain_from_url("") is None
        assert _extract_domain_from_url(None) is None
        assert _extract_domain_from_url("invalid-url") is None
        # Invalid domains should return None to let normal URL validation handle them
        assert _extract_domain_from_url("http://*example.com") is None
        assert _extract_domain_from_url("http://.example.com") is None

    def test_load_allowed_domains_no_file(self):
        """Test loading allowed domains when no file exists."""
        # Temporarily mock the file path to a non-existent location
        import requests.domain_filter as df
        original_func = df._get_allowed_domains_file_path
        df._get_allowed_domains_file_path = lambda: "/nonexistent/path/allowed_domains.json"
        
        try:
            result = _load_allowed_domains()
            assert result is None
        finally:
            df._get_allowed_domains_file_path = original_func

    def test_load_allowed_domains_valid_file(self):
        """Test loading allowed domains from a valid file."""
        test_domains = ["example.com", "test.org", "localhost"]
        test_config = {"allowed_domains": test_domains}
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            result = _load_allowed_domains()
            assert result == test_domains
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)

    def test_load_allowed_domains_invalid_json(self):
        """Test loading allowed domains from invalid JSON file."""
        # Create a temporary file with invalid JSON
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content")
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            result = _load_allowed_domains()
            assert result is None
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)

    def test_is_domain_allowed_no_config(self):
        """Test domain checking when no configuration exists."""
        # Mock no configuration file
        import requests.domain_filter as df
        original_func = df._get_allowed_domains_file_path
        df._get_allowed_domains_file_path = lambda: "/nonexistent/path/allowed_domains.json"
        
        try:
            # Should allow all domains when no config exists
            assert is_domain_allowed("https://example.com") is True
            assert is_domain_allowed("https://anysite.org") is True
        finally:
            df._get_allowed_domains_file_path = original_func

    def test_is_domain_allowed_with_config(self):
        """Test domain checking with a configuration file."""
        test_domains = ["example.com", "trusted.org"]
        test_config = {"allowed_domains": test_domains}
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            # Test allowed domains
            assert is_domain_allowed("https://example.com/path") is True
            assert is_domain_allowed("http://trusted.org:8080") is True
            
            # Test disallowed domains
            assert is_domain_allowed("https://malicious.com") is False
            assert is_domain_allowed("http://untrusted.net") is False
            
            # Test edge cases
            assert is_domain_allowed("") is True  # Can't extract domain
            assert is_domain_allowed(None) is True  # Can't extract domain
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)

    def test_validate_domain_or_raise_allowed(self):
        """Test domain validation for allowed domains."""
        test_domains = ["example.com"]
        test_config = {"allowed_domains": test_domains}
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            # Should not raise for allowed domain
            validate_domain_or_raise("https://example.com/path")
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)

    def test_validate_domain_or_raise_blocked(self):
        """Test domain validation for blocked domains."""
        test_domains = ["example.com"]
        test_config = {"allowed_domains": test_domains}
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            # Should raise for blocked domain
            with pytest.raises(DomainFilterError) as exc_info:
                validate_domain_or_raise("https://blocked.com/path")
            
            assert "blocked.com" in str(exc_info.value)
            assert "not in the allowed domains list" in str(exc_info.value)
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)


class TestRequestsDomainFiltering:
    """Test requests.get() and requests.post() with domain filtering."""

    def test_requests_get_allowed_domain(self):
        """Test requests.get() with an allowed domain."""
        test_domains = ["httpbin.org"]
        test_config = {"allowed_domains": test_domains}
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            # Should not raise for allowed domain (even if network fails)
            try:
                requests.get("https://httpbin.org/get")
            except requests.exceptions.ConnectionError:
                # Expected due to network limitations in test environment
                pass
            except DomainFilterError:
                pytest.fail("DomainFilterError should not be raised for allowed domain")
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)

    def test_requests_get_blocked_domain(self):
        """Test requests.get() with a blocked domain."""
        test_domains = ["example.com"]
        test_config = {"allowed_domains": test_domains}
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            # Should raise DomainFilterError for blocked domain
            with pytest.raises(DomainFilterError) as exc_info:
                requests.get("https://blocked.com/get")
            
            assert "blocked.com" in str(exc_info.value)
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)

    def test_requests_post_allowed_domain(self):
        """Test requests.post() with an allowed domain."""
        test_domains = ["httpbin.org"]
        test_config = {"allowed_domains": test_domains}
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            # Should not raise for allowed domain (even if network fails)
            try:
                requests.post("https://httpbin.org/post", data={"key": "value"})
            except requests.exceptions.ConnectionError:
                # Expected due to network limitations in test environment
                pass
            except DomainFilterError:
                pytest.fail("DomainFilterError should not be raised for allowed domain")
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)

    def test_requests_post_blocked_domain(self):
        """Test requests.post() with a blocked domain."""
        test_domains = ["example.com"]
        test_config = {"allowed_domains": test_domains}
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(test_config, f)
            temp_file_path = f.name
        
        try:
            # Temporarily mock the file path
            import requests.domain_filter as df
            original_func = df._get_allowed_domains_file_path
            df._get_allowed_domains_file_path = lambda: temp_file_path
            
            # Should raise DomainFilterError for blocked domain
            with pytest.raises(DomainFilterError) as exc_info:
                requests.post("https://blocked.com/post", data={"key": "value"})
            
            assert "blocked.com" in str(exc_info.value)
        finally:
            df._get_allowed_domains_file_path = original_func
            os.unlink(temp_file_path)

    def test_requests_no_config_file_allows_all(self):
        """Test that requests work normally when no config file exists."""
        # Mock no configuration file
        import requests.domain_filter as df
        original_func = df._get_allowed_domains_file_path
        df._get_allowed_domains_file_path = lambda: "/nonexistent/path/allowed_domains.json"
        
        try:
            # Should allow all domains when no config exists (even if network fails)
            try:
                requests.get("https://any-domain.com/get")
            except requests.exceptions.ConnectionError:
                # Expected due to network limitations in test environment
                pass
            except DomainFilterError:
                pytest.fail("DomainFilterError should not be raised when no config file exists")
        finally:
            df._get_allowed_domains_file_path = original_func