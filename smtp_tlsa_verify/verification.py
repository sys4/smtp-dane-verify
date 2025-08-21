import time
import subprocess
from typing import Optional, List

import dns.rdtypes.ANY.TLSA
import pydantic

from smtp_tlsa_verify.dns_records import (
    TlsaRecordError,
    filter_tlsa_resource_records,
    get_tlsa_record,
)


class VerificationResult(pydantic.BaseModel):
    is_valid: bool = False
    protocol_version: Optional[str] = None
    hostname: Optional[str] = None
    ciphersuite: Optional[str] = None
    peer_certificate: Optional[str] = None
    hash_used: Optional[str] = None
    signature_type: Optional[str] = None
    verification: Optional[str] = None
    openssl_return_code: Optional[int] = None
    message: Optional[str] = None


def verify_tlsa_resource_record(
    hostname: str,
    answers: List[dns.rdtypes.ANY.TLSA.TLSA],
    addr: Optional[str] = None,
    openssl: Optional[str] = None,
) -> VerificationResult:
    if addr is None:
        connect_addr = hostname
    else:
        connect_addr = addr

    if openssl is None:
        openssl_path = "openssl"
    else:
        openssl_path = openssl

    # Turn the list of TLSA answers into options for openssl, looks like this:
    # -dane_tlsa_rrdata 3 1 1 E41CC......
    rrdata = []
    for answer in answers:
        rrdata.append("-dane_tlsa_rrdata")
        rrdata.append(f'"{answer.to_text().upper()}"')

    sslopts = [
        f"{openssl_path}",
        "s_client",
        "-brief",
        "-starttls",
        "smtp",
        "-connect",
        f"{connect_addr}:25",
        # TODO: "${sigs[@]}" -sigalgs" "$rsa" -cipher aRSA
        "-verify",
        "9",
        "-verify_return_error",
        "-dane_ee_no_namechecks",
        "-dane_tlsa_domain",
        f"{hostname}",
    ] + rrdata
    input = b"QUIT\n"
    try:
        p = subprocess.Popen(
            " ".join(sslopts),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
        )
        lines = []
        result = VerificationResult(hostname=hostname)
        while True:
            if not p.poll() is None:
                break
            time.sleep(0.0125)
            stdout, stderr = p.communicate(input=input, timeout=10.0)
            if stdout:
                for line in stdout.decode().splitlines():
                    print(line)
            if stderr:
                for line in stderr.decode().splitlines():
                    if line.startswith("Protocol version:"):
                        result.protocol_version = line.split(":", 1)[1].strip()
                        continue
                    if line.startswith("Ciphersuite:"):
                        result.ciphersuite = line.split(":", 1)[1].strip()
                        continue
                    if line.startswith("Peer certificate:"):
                        result.peer_certificate = line.split(":", 1)[1].strip()
                        continue
                    if line.startswith("Hash used:"):
                        result.hash_used = line.split(":", 1)[1].strip()
                        continue
                    if line.startswith("Signature type:"):
                        result.signature_type = line.split(":", 1)[1].strip()
                        continue
                    if line.startswith("Verification:"):
                        verification = line.split(":", 1)[1].strip()
                        result.verification = verification
                        if verification == "OK":
                            result.is_valid = True
                        continue
        retval = p.wait()
        result.openssl_return_code = retval
        return result
    except subprocess.SubprocessError as err:
        return VerificationResult(
            is_valid=False,
            hostname=hostname,
            message=f"{err}",
        )


def verify(hostname: str, openssl: Optional[str] = None) -> VerificationResult:
    try:
        answers = get_tlsa_record(hostname)
    except TlsaRecordError as err:
        result = VerificationResult(hostname=hostname)
        result.message = f"{err}"
        return result

    filtered_answers = filter_tlsa_resource_records(answers)
    result = verify_tlsa_resource_record(hostname, filtered_answers, openssl=openssl)
    return result
