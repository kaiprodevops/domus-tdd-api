"""
Security validation module to prevent SPARQL and RDF injection attacks.
Enforces strict schema compliance and character allowlisting before data reaches the database layer.
"""

import re
import logging
import hashlib
from typing import List, Optional

from .errors import SecurityValidationError

# Initialize module-level logger for security auditing
logger = logging.getLogger(__name__)

# Strict regex for URI validation (RFC 3986 compliant).
# Allows standard URI characters INCLUDING percent-encoding ('%').
# Explicitly rejects structural SPARQL characters ('<', '>', '{', '}', '^', '`', '|', '\\', spaces).
# This ensures attackers cannot break out of the <URI> wrapper in SPARQL queries.
URI_REGEX = re.compile(r"^[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")


def _input_fingerprint(value: str) -> str:
    """Return a short non-reversible fingerprint for safe security logs."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def validate_uri(uri: str) -> str:
    """
    Validates a URI string against injection patterns.

    This function enforces a strict allowlist of RFC 3986 compliant characters
    to prevent SPARQL injection attacks. It blocks structural characters that
    could break out of SPARQL query templates.

    Args:
        uri: The URI string to validate (from user input)

    Returns:
        The validated URI string (unchanged if valid)

    Raises:
        SecurityValidationError: If the URI contains unsafe characters or is not a string

    Security Notes:
        - Logs only non-reversible fingerprints (never attacker input)
        - Returns generic error message to prevent attackers from probing validation rules
    """
    if not isinstance(uri, str) or not URI_REGEX.match(uri):
        if isinstance(uri, str):
            logger.warning(
                "SECURITY ALERT: Malformed or unsafe URI blocked. fingerprint=%s length=%d",
                _input_fingerprint(uri),
                len(uri),
            )
        else:
            logger.warning(
                "SECURITY ALERT: Malformed or unsafe URI blocked. type=%s",
                type(uri).__name__,
            )
        # Generic error message - do not echo user input to prevent information leakage
        raise SecurityValidationError("Malformed or unsafe URI detected.")
    return uri


def validate_uris(uris: List[str]) -> List[str]:
    """
    Validates a list of URIs.
    """
    if not isinstance(uris, list):
        logger.warning(
            "SECURITY ALERT: Expected a list of URIs, received different type."
        )
        raise SecurityValidationError("Expected a list of URIs.")
    return [validate_uri(u) for u in uris]


def validate_sort_order(sort_order: Optional[str]) -> Optional[str]:
    """
    Validates and normalizes sort order parameter using strict allowlist.

    This prevents SPARQL injection through the ORDER BY clause by only
    allowing "ASC" or "DESC" values.

    Args:
        sort_order: The sort order string ("asc", "desc", empty string, or None)

    Returns:
        Normalized sort order ("ASC", "DESC", or None for empty/None input)

    Raises:
        SecurityValidationError: If sort order is not in the allowlist

    Examples:
        >>> validate_sort_order("asc")
        "ASC"
        >>> validate_sort_order("DESC")
        "DESC"
        >>> validate_sort_order(None)
        None
        >>> validate_sort_order("")
        None
    """
    if not sort_order:
        return None

    normalized_order = sort_order.strip().upper()

    # After stripping, check if it's empty
    if not normalized_order:
        return None

    if normalized_order not in ["ASC", "DESC"]:
        logger.warning(
            "SECURITY ALERT: Invalid sort order blocked. fingerprint=%s length=%d",
            _input_fingerprint(sort_order),
            len(sort_order),
        )
        raise SecurityValidationError("Invalid sort order.")
    return normalized_order
