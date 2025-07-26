import unittest
from unittest.mock import patch

import dns.resolver  # Will be mocked

# Unit under test
from smtp_tlsa_verify.dns_records import get_tlsa_record


class TestGetTLSARecord:

    @patch('smtp_tlsa_verify.dns_records.dns.resolver.resolve')
    def test_get_tlsa_record_success(self, mock_resolve):
        # Mock the DNS resolver to return a sample TLSA record
        mock_answer = unittest.mock.Mock()
        mock_answer.to_text.return_value = '3 1 1 1234567890abcdef1234567890abcdef1234567890abcdef'
        mock_resolve.return_value = [mock_answer]

        # Call the function
        result = get_tlsa_record('example.com')

        # Check the result
        assert result == ['3 1 1 1234567890abcdef1234567890abcdef1234567890abcdef']

    @patch('smtp_tlsa_verify.dns_records.dns.resolver.resolve')
    def test_get_tlsa_record_no_answer(self, mock_resolve):
        # Mock the DNS resolver to raise NoAnswer
        mock_resolve.side_effect = dns.resolver.NoAnswer

        # Call the function
        result = get_tlsa_record('example.com')

        # Check the result
        assert result == []

    @patch('smtp_tlsa_verify.dns_records.dns.resolver.resolve')
    def test_get_tlsa_record_nxdomain(self, mock_resolve):
        # Mock the DNS resolver to raise NXDOMAIN
        mock_resolve.side_effect = dns.resolver.NXDOMAIN

        # Call the function
        result = get_tlsa_record('example.com')

        # Check the result
        assert result == []

    @patch('smtp_tlsa_verify.dns_records.dns.resolver.resolve')
    def test_get_tlsa_record_timeout(self, mock_resolve):
        # Mock the DNS resolver to raise Timeout
        mock_resolve.side_effect = dns.resolver.Timeout

        # Call the function
        result = get_tlsa_record('example.com')

        # Check the result
        assert result == []

    @patch('smtp_tlsa_verify.dns_records.dns.resolver.resolve')
    def test_get_tlsa_record_exception(self, mock_resolve):
        # Mock the DNS resolver to raise a generic exception
        mock_resolve.side_effect = Exception('Test exception')

        # Call the function
        result = get_tlsa_record('example.com')

        # Check the result
        self