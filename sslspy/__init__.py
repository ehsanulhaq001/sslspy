"""
SSLSpy - SSL/TLS Security Scanner
================================

A comprehensive tool for analyzing and monitoring SSL/TLS security:
- Certificate expiration dates
- Protocol versions (TLS 1.0, 1.1, 1.2, 1.3)
- Cipher suites
- Certificate chains
- Security vulnerabilities

Basic usage:

    from sslspy import check_domains

    results = check_domains(['example.com', 'google.com'])
    print(results)
"""

__version__ = "0.1.0"

from sslspy.checker import check_domain, check_domains
from sslspy.constants import (
    STATUS_VALID,
    STATUS_WARNING,
    STATUS_EXPIRED,
    STATUS_TIMEOUT,
    STATUS_ERROR,
)

__all__ = [
    "check_domain",
    "check_domains",
    "STATUS_VALID",
    "STATUS_WARNING",
    "STATUS_EXPIRED",
    "STATUS_TIMEOUT",
    "STATUS_ERROR",
]
