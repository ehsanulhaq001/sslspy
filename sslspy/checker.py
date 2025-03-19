"""Core functionality for SSL/TLS security analysis."""

import ssl
import socket
import datetime
import concurrent.futures
import time
from typing import List, Dict, Any, Optional, Tuple

from sslspy.constants import (
    STATUS_VALID,
    STATUS_WARNING,
    STATUS_EXPIRED,
    STATUS_TIMEOUT,
    STATUS_ERROR,
    DEFAULT_TIMEOUT,
    DEFAULT_WARNING_THRESHOLD,
    EXITING,
    PAUSED,
)


def check_domain(
    domain: str,
    timeout: int = DEFAULT_TIMEOUT,
    warning_threshold: int = DEFAULT_WARNING_THRESHOLD,
) -> Dict[str, Any]:
    """
    Check the SSL certificate for a domain.

    Args:
        domain: The domain to check
        timeout: Connection timeout in seconds
        warning_threshold: Number of days before expiry to trigger warning status

    Returns:
        Dictionary containing check results
    """
    # Default return values
    status = STATUS_ERROR
    days_left = None
    error_msg = None
    expiry_date = None

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # Create a TCP socket
        sock.connect((domain, 443))

        # Wrap with SSL
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=domain) as ssock:
            # SSL handshake happens here
            cert = ssock.getpeercert()

            # Extract the notAfter date
            if not cert or "notAfter" not in cert:
                raise ssl.SSLError("Certificate not valid or missing expiration date.")

            # Parse expiration date
            # notAfter is typically in the format 'Apr  9 12:00:00 2025 GMT'
            not_after_str = cert["notAfter"]
            expiry_time = datetime.datetime.strptime(
                not_after_str, "%b %d %H:%M:%S %Y GMT"
            )
            expiry_date = expiry_time.strftime("%Y-%m-%d")

            remaining = expiry_time - datetime.datetime.utcnow()
            days_left = remaining.days

            # Determine status from days_left
            if days_left < 0:
                status = STATUS_EXPIRED
            elif days_left < warning_threshold:
                status = STATUS_WARNING
            else:
                status = STATUS_VALID

    except socket.timeout:
        status = STATUS_TIMEOUT
        error_msg = "Connection timed out"
    except ssl.SSLError as e:
        status = STATUS_ERROR
        error_msg = f"SSL error: {e}"
    except Exception as e:
        # Could be DNS error, refused connection, etc.
        status = STATUS_ERROR
        error_msg = f"{type(e).__name__}: {e}"
    finally:
        sock.close()

    return {
        "domain": domain,
        "status": status,
        "days_left": days_left,
        "expiry_date": expiry_date,
        "error_msg": error_msg,
    }


def check_domains(
    domains: List[str],
    timeout: int = DEFAULT_TIMEOUT,
    warning_threshold: int = DEFAULT_WARNING_THRESHOLD,
    max_workers: int = 20,
    callback=None,
) -> List[Dict[str, Any]]:
    """
    Check SSL certificates for multiple domains in parallel.

    Args:
        domains: List of domains to check
        timeout: Connection timeout in seconds
        warning_threshold: Days before expiry to trigger warning
        max_workers: Maximum number of concurrent workers
        callback: Optional callback function called with (result, completed, total)

    Returns:
        List of result dictionaries
    """
    results = []
    total = len(domains)
    completed = 0

    # Flag to track if execution was interrupted
    interrupted = False

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(check_domain, d, timeout, warning_threshold): d
            for d in domains
        }

        try:
            for future in concurrent.futures.as_completed(future_to_domain):
                try:
                    # Get the current state
                    from sslspy.constants import EXITING, PAUSED

                    # Check if we need to exit
                    if EXITING or interrupted:
                        # Cancel all pending futures
                        for f in future_to_domain:
                            if not f.done():
                                f.cancel()
                        break

                    # Check if we're paused - wait until unpaused
                    while PAUSED and not EXITING:
                        time.sleep(0.1)
                        # Refresh the state (in case it changed while sleeping)
                        from sslspy.constants import EXITING, PAUSED

                    # Skip processing if we decided to exit during pause
                    if EXITING:
                        break

                    result = future.result()
                    results.append(result)
                    completed += 1

                    if callback:
                        callback(result, completed, total)
                except KeyboardInterrupt:
                    # Mark as interrupted and propagate
                    interrupted = True
                    raise
                except Exception as e:
                    # Handle any other exceptions from the future
                    result = {
                        "domain": future_to_domain[future],
                        "status": STATUS_ERROR,
                        "days_left": None,
                        "expiry_date": None,
                        "error_msg": f"Unexpected error: {str(e)}",
                    }
                    results.append(result)
                    completed += 1
                    if callback:
                        callback(result, completed, total)
        except KeyboardInterrupt:
            # Cancel all pending futures when interrupted
            for f in future_to_domain:
                if not f.done():
                    f.cancel()
            raise

    return results
