"""******************************************************************************
* Copyright (c) 2018 Contributors to the Eclipse Foundation
*
* See the NOTICE file(s) distributed with this work for additional
* information regarding copyright ownership.
*
* This program and the accompanying materials are made available under the
* terms of the Eclipse Public License v. 2.0 which is available at
* http://www.eclipse.org/legal/epl-2.0, or the W3C Software Notice and
* Document License (2015-05-13) which is available at
* https://www.w3.org/Consortium/Legal/2015/copyright-software-and-document.
*
* SPDX-License-Identifier: EPL-2.0 OR W3C-20150513
********************************************************************************

Unit tests for security validators module.

These tests ensure that the validation layer correctly blocks SPARQL injection
attempts while allowing legitimate URIs and parameters to pass through.
"""

import pytest
from tdd.validators import validate_uri, validate_sort_order, validate_uris
from tdd.errors import SecurityValidationError


class TestValidateUri:
    """Test suite for URI validation against SPARQL injection."""

    def test_valid_http_uris(self):
        """Test that valid HTTP/HTTPS URIs pass validation."""
        valid_uris = [
            "https://example.com/td/1",
            "http://localhost:3030/things",
            "https://www.w3.org/2019/wot/td",
            "http://example.com:8080/path/to/resource",
        ]
        for uri in valid_uris:
            assert validate_uri(uri) == uri

    def test_valid_urn_uris(self):
        """Test that valid URN URIs pass validation."""
        valid_urns = [
            "urn:uuid:12345678-1234-5678-1234-567812345678",
            "urn:dev:ops:my-thing-1234",
            "urn:example:animal:ferret:nose",
        ]
        for urn in valid_urns:
            assert validate_uri(urn) == urn

    def test_valid_percent_encoded_uris(self):
        """Test that percent-encoded URIs pass validation."""
        valid_encoded = [
            "http://example.com/path%20with%20spaces",
            "http://example.com/query?name=John%20Doe",
            "urn:uuid:test%2Fslash",
        ]
        for uri in valid_encoded:
            assert validate_uri(uri) == uri

    def test_uri_with_query_parameters(self):
        """Test that URIs with query parameters pass validation."""
        uri = "http://example.com/path?query=value&foo=bar&baz=123"
        assert validate_uri(uri) == uri

    def test_uri_with_fragment(self):
        """Test that URIs with fragments pass validation."""
        uri = "http://example.com/path#section"
        assert validate_uri(uri) == uri

    def test_uri_with_special_allowed_chars(self):
        """Test that URIs with RFC 3986 allowed special characters pass."""
        uri = "http://example.com/path!$&'()*+,;=test"
        assert validate_uri(uri) == uri

    def test_reject_uri_with_angle_brackets(self):
        """Test that URIs containing angle brackets are rejected (SPARQL injection risk)."""
        malicious_uris = [
            "http://example.com/<script>",
            "urn:test> } DROP GRAPH <ALL>",
            "http://example.com/path>malicious",
        ]
        for uri in malicious_uris:
            with pytest.raises(SecurityValidationError) as exc_info:
                validate_uri(uri)
            # Verify error message is generic and doesn't contain user input
            assert exc_info.value.message == "Malformed or unsafe URI detected."
            assert uri not in exc_info.value.message

    def test_reject_uri_with_curly_braces(self):
        """Test that URIs containing curly braces are rejected (SPARQL injection risk)."""
        malicious_uris = [
            "http://example.com/{malicious}",
            "urn:test} UNION {",
            "http://example.com/path{injection",
        ]
        for uri in malicious_uris:
            with pytest.raises(SecurityValidationError):
                validate_uri(uri)

    def test_reject_uri_with_newlines(self):
        """Test that URIs containing newlines are rejected (log injection risk)."""
        malicious_uris = [
            "http://example.com/\nmalicious",
            "urn:test\n; DELETE WHERE { ?s ?p ?o }",
            "http://example.com/path\r\ninjection",
        ]
        for uri in malicious_uris:
            with pytest.raises(SecurityValidationError):
                validate_uri(uri)

    def test_reject_uri_with_spaces(self):
        """Test that URIs containing unencoded spaces are rejected."""
        malicious_uris = [
            "http://example.com/ space",
            "urn:test space",
            "http://example.com/path with spaces",
        ]
        for uri in malicious_uris:
            with pytest.raises(SecurityValidationError):
                validate_uri(uri)

    def test_reject_sparql_injection_payloads(self):
        """Test that known SPARQL injection payloads are blocked."""
        injection_payloads = [
            "urn:test> } ; DROP GRAPH <ALL> ; #",
            "http://example.com/} UNION { ?s ?p ?o }",
            "urn:uuid:123> ; DELETE WHERE { ?s ?p ?o } ; <urn:fake",
            "http://test.com/> } CONSTRUCT { ?s ?p ?o } WHERE { <urn:evil",
        ]
        for payload in injection_payloads:
            with pytest.raises(SecurityValidationError):
                validate_uri(payload)

    def test_reject_empty_string(self):
        """Test that empty strings are rejected."""
        with pytest.raises(SecurityValidationError):
            validate_uri("")

    def test_reject_none(self):
        """Test that None values are rejected."""
        with pytest.raises(SecurityValidationError):
            validate_uri(None)

    def test_reject_non_string_types(self):
        """Test that non-string types are rejected."""
        invalid_types = [
            123,
            ["http://example.com"],
            {"uri": "http://example.com"},
            True,
        ]
        for invalid_input in invalid_types:
            with pytest.raises(SecurityValidationError):
                validate_uri(invalid_input)

    def test_uri_validation_boundary_characters(self):
        """Test boundary cases for allowed vs disallowed characters."""
        # Should pass - all RFC 3986 allowed characters
        allowed_chars_uri = "http://example.com/~user_name-123.test?q=a&b=c#frag"
        assert validate_uri(allowed_chars_uri) == allowed_chars_uri

        # Should fail - contains disallowed structural characters
        disallowed_chars = ["<", ">", "{", "}", "\\", "|", "^", "`", " "]
        for char in disallowed_chars:
            malicious_uri = f"http://example.com/test{char}malicious"
            with pytest.raises(SecurityValidationError):
                validate_uri(malicious_uri)


class TestValidateUris:
    """Test suite for batch URI validation."""

    def test_valid_uri_list(self):
        """Test that a list of valid URIs passes validation."""
        valid_list = [
            "http://example.com/td1",
            "http://example.com/td2",
            "urn:uuid:12345678-1234-5678-1234-567812345678",
        ]
        assert validate_uris(valid_list) == valid_list

    def test_empty_list(self):
        """Test that an empty list is valid."""
        assert validate_uris([]) == []

    def test_reject_list_with_invalid_uri(self):
        """Test that a list containing any invalid URI is rejected."""
        mixed_list = [
            "http://example.com/valid",
            "http://example.com/<malicious>",  # Invalid
            "urn:uuid:valid",
        ]
        with pytest.raises(SecurityValidationError):
            validate_uris(mixed_list)

    def test_reject_non_list_input(self):
        """Test that non-list inputs are rejected."""
        invalid_inputs = [
            "http://example.com",  # String instead of list
            None,
            123,
            {"uri": "http://example.com"},
        ]
        for invalid_input in invalid_inputs:
            with pytest.raises(SecurityValidationError):
                validate_uris(invalid_input)


class TestValidateSortOrder:
    """Test suite for sort order parameter validation."""

    def test_normalize_lowercase_asc(self):
        """Test that lowercase 'asc' is normalized to 'ASC'."""
        assert validate_sort_order("asc") == "ASC"

    def test_normalize_uppercase_asc(self):
        """Test that uppercase 'ASC' remains 'ASC'."""
        assert validate_sort_order("ASC") == "ASC"

    def test_normalize_mixed_case_asc(self):
        """Test that mixed case 'Asc' is normalized to 'ASC'."""
        assert validate_sort_order("Asc") == "ASC"

    def test_normalize_lowercase_desc(self):
        """Test that lowercase 'desc' is normalized to 'DESC'."""
        assert validate_sort_order("desc") == "DESC"

    def test_normalize_uppercase_desc(self):
        """Test that uppercase 'DESC' remains 'DESC'."""
        assert validate_sort_order("DESC") == "DESC"

    def test_normalize_mixed_case_desc(self):
        """Test that mixed case 'Desc' is normalized to 'DESC'."""
        assert validate_sort_order("Desc") == "DESC"

    def test_handle_none_input(self):
        """Test that None input returns None."""
        assert validate_sort_order(None) is None

    def test_handle_empty_string(self):
        """Test that empty string returns None."""
        assert validate_sort_order("") is None

    def test_strip_whitespace(self):
        """Test that leading/trailing whitespace is stripped before validation."""
        assert validate_sort_order("  asc  ") == "ASC"
        assert validate_sort_order("  DESC  ") == "DESC"

    def test_whitespace_only_returns_none(self):
        """Test that whitespace-only string returns None after stripping."""
        assert validate_sort_order("   ") is None
        assert validate_sort_order("\t\n") is None

    def test_reject_invalid_values(self):
        """Test that values not in allowlist are rejected without echoing user input."""
        invalid_values = [
            "invalid",
            "DROP",
            "UNION",
            "1",
            "true",
            "ascending",
            "descending",
        ]
        for value in invalid_values:
            with pytest.raises(SecurityValidationError) as exc_info:
                validate_sort_order(value)
            # Verify error message is generic and doesn't contain user input
            assert exc_info.value.message == "Invalid sort order."
            assert value not in exc_info.value.message

    def test_reject_sparql_injection_attempts(self):
        """
        Test that SPARQL injection attempts through sort_order are
        blocked without echoing input.
        """
        injection_attempts = [
            "ASC; DROP GRAPH <ALL>",
            "DESC) UNION (SELECT",
            "ASC\n; DELETE WHERE",
        ]
        for attempt in injection_attempts:
            with pytest.raises(SecurityValidationError) as exc_info:
                validate_sort_order(attempt)
            # Verify error message is generic and doesn't contain user input
            assert exc_info.value.message == "Invalid sort order."
            assert attempt not in exc_info.value.message


class TestValidationIntegration:
    """Integration tests for validator interactions."""

    def test_validate_uris_calls_validate_uri(self):
        """Test that validate_uris properly validates each URI in the list."""
        # This should pass
        valid_list = ["http://example.com/1", "http://example.com/2"]
        result = validate_uris(valid_list)
        assert result == valid_list

        # This should fail on the second URI
        invalid_list = ["http://example.com/valid", "http://example.com/<invalid>"]
        with pytest.raises(SecurityValidationError):
            validate_uris(invalid_list)

    def test_uri_validation_preserves_order(self):
        """Test that URI list validation preserves the original order."""
        uri_list = [
            "urn:uuid:aaaaaaaa-1111-2222-3333-444444444444",
            "http://example.com/first",
            "http://example.com/second",
            "urn:uuid:bbbbbbbb-5555-6666-7777-888888888888",
        ]
        result = validate_uris(uri_list)
        assert result == uri_list

    def test_error_messages_never_echo_dangerous_input(self):
        """
        Explicit test that error messages do not leak user input.

        This is a critical security requirement to prevent:
        1. Information leakage - attackers probing the validation rules
        2. Log injection - malicious input corrupting log files
        """
        dangerous_sort_orders = [
            "DROP GRAPH <ALL>",
            "'; DELETE WHERE { ?s ?p ?o }",
            "UNION { ?s ?p ?o }",
            "\n; MALICIOUS COMMAND",
            "ASC\r\nINJECTED_LOG_ENTRY",
        ]

        for dangerous_input in dangerous_sort_orders:
            try:
                validate_sort_order(dangerous_input)
                pytest.fail(
                    f"Should have raised SecurityValidationError for: {dangerous_input}"
                )
            except SecurityValidationError as e:
                # Critical: verify the dangerous input is NOT in the error message
                assert dangerous_input not in e.message, (
                    f"SECURITY VULNERABILITY: Error message leaked user input. "
                    f"Message '{e.message}' contains '{dangerous_input}'"
                )
                # Verify it's the expected generic message
                assert e.message == "Invalid sort order."

        dangerous_uris = [
            "urn:test> } ; DROP GRAPH <ALL>",
            "http://example.com/\nINJECTED_LOG",
            "http://test.com/<script>alert('xss')</script>",
        ]

        for dangerous_input in dangerous_uris:
            try:
                validate_uri(dangerous_input)
                pytest.fail(
                    f"Should have raised SecurityValidationError for: {dangerous_input}"
                )
            except SecurityValidationError as e:
                # Critical: verify the dangerous input is NOT in the error message
                assert dangerous_input not in e.message, (
                    f"SECURITY VULNERABILITY: Error message leaked user input. "
                    f"Message '{e.message}' contains '{dangerous_input}'"
                )
                # Verify it's the expected generic message
                assert e.message == "Malformed or unsafe URI detected."


class TestLogSecurity:
    """Test suite to verify that logs do not leak sensitive user input."""

    def test_uri_validation_logs_do_not_contain_raw_input(self, caplog):
        """
        Test that log entries include fingerprint metadata, never raw malicious input.

        This prevents:
        1. Log injection attacks (e.g., newlines corrupting log structure)
        2. Information leakage through log files
        """
        dangerous_uris = [
            "http://example.com/\nINJECTED_LOG_ENTRY",
            "urn:test> } ; DROP GRAPH <ALL>",
            "http://test.com/<script>alert('xss')</script>",
        ]

        for dangerous_uri in dangerous_uris:
            caplog.clear()

            try:
                validate_uri(dangerous_uri)
            except SecurityValidationError:
                pass  # Expected

            # Verify log was created
            assert len(caplog.records) == 1
            log_message = caplog.records[0].message

            # Critical: raw dangerous input should NOT be in the log
            assert dangerous_uri not in log_message, (
                f"SECURITY ISSUE: Log contains raw malicious input. "
                f"Log: '{log_message}' contains '{dangerous_uri}'"
            )

            # Verify log contains safe metadata only
            assert "fingerprint=" in log_message
            assert "length=" in log_message

    def test_sort_order_validation_logs_do_not_contain_raw_input(self, caplog):
        """
        Test that sort_order validation logs use fingerprint metadata and don't leak raw input.
        """
        dangerous_inputs = [
            "ASC\n; DROP GRAPH <ALL>",
            "DESC; DELETE WHERE { ?s ?p ?o }",
            "UNION\r\nINJECTED_LOG",
        ]

        for dangerous_input in dangerous_inputs:
            caplog.clear()

            try:
                validate_sort_order(dangerous_input)
            except SecurityValidationError:
                pass  # Expected

            # Verify log was created
            assert len(caplog.records) == 1
            log_message = caplog.records[0].message

            # Critical: raw dangerous input should NOT be in the log
            assert dangerous_input not in log_message, (
                f"SECURITY ISSUE: Log contains raw malicious input. "
                f"Log: '{log_message}' contains '{dangerous_input}'"
            )

            # Verify log contains safe metadata only
            assert "fingerprint=" in log_message
            assert "length=" in log_message

    def test_log_truncation_prevents_flooding(self, caplog):
        """
        Test that extremely long malicious URIs are logged without raw content.

        This prevents log flooding attacks where attackers send very long
        inputs to fill up disk space or make logs unreadable.
        """
        # Create a very long malicious URI (1000 characters)
        long_malicious_uri = "http://example.com/" + "A" * 1000 + "<DROP>"

        caplog.clear()

        try:
            validate_uri(long_malicious_uri)
        except SecurityValidationError:
            pass  # Expected

        assert len(caplog.records) == 1
        log_message = caplog.records[0].message

        # Verify the full malicious URI is NOT in the log
        assert long_malicious_uri not in log_message

        # The log should contain fixed-size safe metadata instead of snippets
        assert "fingerprint=" in log_message
        assert "length=" in log_message

    def test_non_string_type_logged_safely(self, caplog):
        """
        Test that non-string types are logged as type names, not repr of content.

        This prevents potential issues with logging complex objects.
        """
        non_string_inputs = [
            123,
            ["http://example.com"],
            {"uri": "http://example.com"},
        ]

        for invalid_input in non_string_inputs:
            caplog.clear()

            try:
                validate_uri(invalid_input)
            except SecurityValidationError:
                pass  # Expected

            assert len(caplog.records) == 1
            log_message = caplog.records[0].message

            # Should log the type name, not the actual content
            assert type(invalid_input).__name__ in log_message

            # Should NOT contain the actual malicious content
            assert str(invalid_input) not in log_message
