from dataclasses import dataclass
from unittest.mock import patch
from smtp_tlsa_verify.verification import verify_tlsa_resource_record

@dataclass
class FakeTlsaRecord:
    """Fake TLSA Resource Record that can be filtered."""

    usage: int
    selector: int
    mtype: int
    cert: bytes

    def to_text(self):
        return f"{self.usage} {self.selector} {self.mtype} {self.cert.hex()}"
    

def test_verify_tlsa_resource_record():
    fake_answers = [
        FakeTlsaRecord(
            3, 1, 1,
            bytes.fromhex(
                "236831aeeab41e7bd10dc14320600b245c791b338121383d5a2916f7ef97b49b"
            ),
        )
    ]
    command = ['/mock/bin/openssl', 's_client', '-brief', '-starttls', 'smtp',
               '-connect', 'example.com:25-verify', '9', '-verify_return_error',
               '-dane_ee_no_namechecks', '-dane_tlsa_domainexample.com',
               '-dane_tlsa_rrdata', '3 1 1 236831AEEAB41E7BD10DC14320600B245C791B338121383D5A2916F7EF97B49B']
    with patch('smtp_tlsa_verify.verification.subprocess.call') as mock_call:
        verify_tlsa_resource_record('example.com', fake_answers, openssl='/mock/bin/openssl')
        mock_call.assert_called_once_with(command, shell=True)