import logging
import time
import subprocess
import dns.rdtypes.ANY.TLSA
from typing import Optional, List

import pydantic

log = logging.getLogger(__name__)

from smtp_dane_verify.dns_records import (
    TlsaRecordError,
    filter_tlsa_resource_records,
    get_tlsa_record,
    get_mx_records,
)
from smtp_dane_verify.dnssec import query_dnssec, DNSSECError


class VerificationResult(pydantic.BaseModel):
    host_dane_verified: bool = False
    dnssec_valid: bool = False
    dnssec_status: str = ""
    protocol_version: Optional[str] = None
    hostname: Optional[str] = None
    ciphersuite: Optional[str] = None
    peer_certificate: Optional[str] = None
    hash_used: Optional[str] = None
    signature_type: Optional[str] = None
    openssl_verification: Optional[str] = None
    openssl_return_code: Optional[int] = None
    log_messages: list[str] = []
    tlsa_resource_records: list[str] = []


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
    log.debug("OpenSSL command: %s" % " ".join(sslopts))
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
                    log.debug("Got STDOUT line: %s" % repr(line))
            if stderr:
                for line in stderr.decode().splitlines():
                    log.debug("Got STDERR line: %s" % repr(line))
                    if line.startswith("Protocol version:"):
                        result.protocol_version = line.split(":", 1)[1].strip()
                        continue
                    elif line.startswith("Ciphersuite:"):
                        result.ciphersuite = line.split(":", 1)[1].strip()
                        continue
                    elif line.startswith("Peer certificate:"):
                        result.peer_certificate = line.split(":", 1)[1].strip()
                        continue
                    elif line.startswith("Hash used:"):
                        result.hash_used = line.split(":", 1)[1].strip()
                        continue
                    elif line.startswith("Signature type:"):
                        result.signature_type = line.split(":", 1)[1].strip()
                        continue
                    elif line.startswith("Verification:"):
                        verification = line.split(":", 1)[1].strip()
                        result.openssl_verification = verification
                        if verification == "OK":
                            result.host_dane_verified = True
                        continue
                    else:
                        result.log_messages.append(line)
                        continue
                    
        retval = p.wait()
        result.openssl_return_code = retval
        return result
    except subprocess.SubprocessError as err:
        return VerificationResult(
            host_dane_verified=False,
            hostname=hostname,
            message=f"{err}",
        )


def verify(hostname: str, 
           disable_dnssec: bool=False, 
           external_resolver: Optional[str] = None,
           openssl: Optional[str]=None) -> VerificationResult:
    try:
        answers, dnssec_status, dnssec_message = get_tlsa_record(hostname, external_resolver)
    except TlsaRecordError as err:
        result = VerificationResult(hostname=hostname)
        result.log_messages.append(f"{err}")
        return result

    filtered_answers = filter_tlsa_resource_records(answers)
    # Some domains have TLSA-RRs with e.g. usage=1, we only allow usages "2" and "3".
    if len(filtered_answers) == 0:
        result = VerificationResult(hostname=hostname)
        result.log_messages.append(
            "No suitable TLSA resource records found, check the usage, selector, and matching type parameters."
        )
        if disable_dnssec is False:
            result.dnssec_status = dnssec_message
            result.dnssec_valid = dnssec_status
        return result
    
    result = verify_tlsa_resource_record(hostname, filtered_answers, openssl=openssl)
    result.tlsa_resource_records = [str(x) for x in filtered_answers]

    if disable_dnssec is False:
        result.dnssec_status = dnssec_message
        result.dnssec_valid = dnssec_status
        # TODO: Set the final result 'host_dane_verified' to False if strict DNSSEC is enabled.
    else:
        pass
    return result


class DomainVerificationResult(pydantic.BaseModel):
    all_hosts_dane_verified: bool = False
    dnssec_valid: Optional[bool] = False
    domain: Optional[str] = None
    mx_hosts: List[VerificationResult] = []


def verify_domain_servers(domain: str, 
                  disable_dnssec: bool=False, 
                  external_resolver: Optional[str] = None,
                  openssl: Optional[str]=None) -> DomainVerificationResult:
    """
    Verify all the MX records of one domain.
    """
    mailservers, dnssec_status, dnssec_message = get_mx_records(domain, external_resolver)
    result = DomainVerificationResult(domain=domain)

    for server in mailservers:
        clean_server = server.strip('.')
        server_result = verify(clean_server, disable_dnssec, external_resolver, openssl)
        result.mx_hosts.append(server_result)

    # check all results for determining if all_hosts_dane_verified is True.
    result.all_hosts_dane_verified = all([mx.host_dane_verified for mx in result.mx_hosts])
    
    # check the dnssec_status of all results:
    result.dnssec_valid = all(
        # MX record query
        [dnssec_status] +
        # TLSA-RR queries
        [mx.dnssec_valid for mx in result.mx_hosts]
    )

    # We are done here.
    return result
