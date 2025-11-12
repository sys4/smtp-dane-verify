import unittest
from dataclasses import dataclass
from unittest.mock import patch, PropertyMock, MagicMock, Mock

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
        FAKE_RR = "3 1 1 1234567890abcdef1234567890abcdef1234567890abcdef"
        # Mock the DNS resolver to return a sample TLSA record
        mock_record = Mock(spec=dns.rdtypes.ANY.TLSA.TLSA)
        mock_record.to_text.return_value = FAKE_RR
        mock_answer = MagicMock(
            spec=dns.resolver.Answer,
            response=PropertyMock(extended_errors=Mock(return_value=[])),
        )
        mock_answer.__getitem__.return_value = mock_record
        mock_resolve.return_value = mock_answer

        # Call the function
        result, dnssec_status, dnssec_message = get_tlsa_record("example.com")

        # Check the result
        assert result[0].to_text() \
            == FAKE_RR
        
    @patch("smtp_dane_verify.dns_records.dns.resolver.resolve")
    def test_get_tlsa_broken_record(self, mock_resolve):
        BROKEN_RR = "1 1 0 627E3D0A43F91A7944714887E00BA630E0FC89597BF39FFD736D836A D62C6B01"
        # Mock the DNS resolver to return a sample TLSA record
        mock_record = Mock(spec=dns.rdtypes.ANY.TLSA.TLSA)
        mock_record.to_text.return_value = BROKEN_RR
        mock_answer = MagicMock(
            spec=dns.resolver.Answer,
            response=PropertyMock(extended_errors=Mock(return_value=[])),
        )
        mock_answer.__getitem__.return_value = mock_record
        
        mock_resolve.return_value = mock_answer
        # Call the function
        result, dnssec_status, dnssec_message = get_tlsa_record("_25._tcp.mail.zeromsg.com")

        # Check the result
        assert result[0].to_text() \
            == "1 1 0 627E3D0A43F91A7944714887E00BA630E0FC89597BF39FFD736D836A D62C6B01"

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
