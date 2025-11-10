import unittest
from dataclasses import dataclass
from unittest.mock import patch

import pytest
import dns.resolver  # Will be mocked

# Unit under test
from smtp_dane_verify.dns_records import TlsaRecordError, filter_tlsa_resource_records, get_tlsa_record, get_mx_records


class TestGetMXRecords:
    def test_get_mx_records(self):
        res = get_mx_records('uwekamper.de', '1.1.1.1')
        print(res)


class TestGetTLSARecord:
    @patch("smtp_dane_verify.dns_records.dns.resolver.resolve")
    def test_get_tlsa_record_success(self, mock_resolve):
        # Mock the DNS resolver to return a sample TLSA record
        mock_answer = unittest.mock.Mock()
        mock_answer.to_text.return_value = (
            "3 1 1 1234567890abcdef1234567890abcdef1234567890abcdef"
        )
        mock_resolve.return_value = [mock_answer]

        # Call the function
        result = get_tlsa_record("example.com")

        # Check the result
        assert result[0].to_text() \
            == "3 1 1 1234567890abcdef1234567890abcdef1234567890abcdef"

    @patch("smtp_dane_verify.dns_records.dns.resolver.resolve")
    def test_get_tlsa_record_no_answer(self, mock_resolve):
        # Mock the DNS resolver to raise NoAnswer
        mock_resolve.side_effect = dns.resolver.NoAnswer

        # Call the function
        with pytest.raises(TlsaRecordError) as err:
            result = get_tlsa_record("example.com")

    @patch("smtp_dane_verify.dns_records.dns.resolver.resolve")
    def test_get_tlsa_record_nxdomain(self, mock_resolve):
        # Mock the DNS resolver to raise NXDOMAIN
        mock_resolve.side_effect = dns.resolver.NXDOMAIN

        # Call the function
        with pytest.raises(TlsaRecordError) as err:
            result = get_tlsa_record("example.com")

    @patch("smtp_dane_verify.dns_records.dns.resolver.resolve")
    def test_get_tlsa_record_timeout(self, mock_resolve):
        # Mock the DNS resolver to raise Timeout
        mock_resolve.side_effect = dns.resolver.Timeout

        # Call the function
        with pytest.raises(TlsaRecordError) as err:
            get_tlsa_record("example.com")


    @patch("smtp_dane_verify.dns_records.dns.resolver.resolve")
    def test_get_tlsa_record_exception(self, mock_resolve):
        # Mock the DNS resolver to raise a generic exception
        mock_resolve.side_effect = Exception("Test exception")

        # Call the function
        with pytest.raises(TlsaRecordError) as err:
            get_tlsa_record("example.com")


@dataclass
class FakeTlsaRecord:
    """Fake TLSA Resource Record that can be filtered."""

    usage: int
    selector: int
    mtype: int
    cert: bytes

    def to_text(self):
        return f"{self.usage} {self.selector} {self.mtype} {self.cert.hex()}"


class TestParseTlsaRecord:
    def test_filter_tlsa_resource_records(self):
        fake_answers = [
            FakeTlsaRecord(
                3, 1, 1,
                bytes.fromhex(
                    "236831aeeab41e7bd10dc14320600b245c791b338121383d5a2916f7ef97b49b"
                ),
            ),
            FakeTlsaRecord(
                0, 1, 1,
                bytes.fromhex(
                    "236831aeeab41e7bd10dc14320600b245c791b338121383d5a2916f7ef97b49b"
                ),
            ),
        ]
        result = filter_tlsa_resource_records(fake_answers)
        assert len(result) == 1
        assert result[0].to_text() \
            == "3 1 1 236831aeeab41e7bd10dc14320600b245c791b338121383d5a2916f7ef97b49b"
