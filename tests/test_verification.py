import subprocess
from dataclasses import dataclass
from unittest.mock import patch
from smtp_dane_verify.verification import verify_tlsa_resource_record, verify_domain_servers

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
               '-connect', 'example.com:25', '-verify', '9', '-verify_return_error',
               '-dane_ee_no_namechecks', '-dane_tlsa_domain', 'example.com',
               '-dane_tlsa_rrdata', '"3 1 1 236831AEEAB41E7BD10DC14320600B245C791B338121383D5A2916F7EF97B49B"']
    with patch('smtp_dane_verify.verification.subprocess.Popen') as mock_call:
        verify_tlsa_resource_record('example.com', fake_answers, openssl='/mock/bin/openssl')
        mock_call.assert_called_once_with(' '.join(command), stdin=-1, stdout=-1, stderr=-1, shell=True)


def test_verify_tlsa_resource_record_timeout():
    """
    Check if the correct error message appears when the openssl command 
    runs into a timeout after 10 seconds.
    """
    fake_answers = [
        FakeTlsaRecord(
            3, 1, 1,
            bytes.fromhex(
                "236831aeeab41e7bd10dc14320600b245c791b338121383d5a2916f7ef97b49b"
            ),
        )
    ]
    command = ['/mock/bin/openssl', 's_client', '-brief', '-starttls', 'smtp',
               '-connect', 'example.com:25', '-verify', '9', '-verify_return_error',
               '-dane_ee_no_namechecks', '-dane_tlsa_domain', 'example.com',
               '-dane_tlsa_rrdata', '"3 1 1 236831AEEAB41E7BD10DC14320600B245C791B338121383D5A2916F7EF97B49B"']
    cmd = ' '.join(command)    
    expected_msg = f"Command '{cmd}' timed out after 10.0 seconds"
    with patch(
        'smtp_dane_verify.verification.subprocess.Popen',
        side_effect=subprocess.TimeoutExpired(cmd=cmd, timeout=10.0)
    ) as mock_call:
        result = verify_tlsa_resource_record('example.com', fake_answers, openssl='/mock/bin/openssl')
        mock_call.assert_called_once_with(cmd, stdin=-1, stdout=-1, stderr=-1, shell=True)
        assert result.host_dane_verified == False
        assert result.log_messages == []


def test_verify_domain():
    res = verify_domain_servers('uwekamper.de', external_resolver='1.1.1.1')
    assert res != None
