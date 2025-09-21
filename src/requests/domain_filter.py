"""
requests.domain_filter
~~~~~~~~~~~~~~~~~~~~~~

This module implements domain filtering functionality for the Requests library.

:copyright: (c) 2024 by UmerBaig123.
:license: Apache2, see LICENSE for more details.
"""

import json
import os
from urllib.parse import urlparse

from .exceptions import DomainFilterError


def _get_allowed_domains_file_path():
    """Get the path to the allowed domains JSON file."""
    # Look for the file in the same directory as this module
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(current_dir, "allowed_domains.json")


def _load_allowed_domains():
    """Load allowed domains from the JSON configuration file."""
    file_path = _get_allowed_domains_file_path()
    
    if not os.path.exists(file_path):
        # If no file exists, allow all domains by default
        return None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('allowed_domains', [])
    except (json.JSONDecodeError, IOError, KeyError):
        # If there's an error reading the file, allow all domains by default
        return None


def _extract_domain_from_url(url):
    """Extract domain from URL."""
    if not url:
        return None
    
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        # Only return hostname if it looks like a valid domain
        # Invalid domains like '*example.com' or '.example.com' should be ignored
        # to let the normal URL validation handle them
        if hostname and not hostname.startswith('*') and not hostname.startswith('.'):
            return hostname
        return None
    except Exception:
        return None


def is_domain_allowed(url):
    """
    Check if a domain is allowed based on the allowed_domains.json configuration.
    
    :param url: The URL to check
    :return: True if domain is allowed, False otherwise
    :rtype: bool
    """
    allowed_domains = _load_allowed_domains()
    
    # If no configuration file exists or is empty, allow all domains
    if allowed_domains is None:
        return True
    
    domain = _extract_domain_from_url(url)
    
    # If we can't extract a domain, allow the request
    if not domain:
        return True
    
    # Check if domain is in the allowed list
    return domain in allowed_domains


def validate_domain_or_raise(url):
    """
    Validate domain and raise DomainFilterError if not allowed.
    
    :param url: The URL to check
    :raises DomainFilterError: If the domain is not allowed
    """
    if not is_domain_allowed(url):
        domain = _extract_domain_from_url(url)
        raise DomainFilterError(f"Domain '{domain}' is not in the allowed domains list")