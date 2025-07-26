import time
import subprocess
from typing import Optional, List

import dns.rdtypes.ANY.TLSA


def verify_tlsa_resource_record(hostname: str, answers: List[dns.rdtypes.ANY.TLSA.TLSA], addr: Optional[str]=None, openssl: Optional[str]=None) -> int:
    if addr is None:
        connect_addr = hostname
    else:
        connect_addr = addr

    if openssl is None:
        openssl_path = 'openssl'
    else:
        openssl_path = openssl

    # Turn the list of TLSA answers into options for openssl, looks like this:
    # -dane_tlsa_rrdata 3 1 1 E41CC......
    rrdata = []
    for answer in answers:
        rrdata.append('-dane_tlsa_rrdata')
        rrdata.append(f'"{answer.to_text().upper()}"')
    
    sslopts = [
        f"{openssl_path}", "s_client", 
        "-brief",
        "-starttls", "smtp",  
        "-connect", f"{connect_addr}:25", 
        # TODO: "${sigs[@]}" -sigalgs" "$rsa" -cipher aRSA
        "-verify", "9",
        "-verify_return_error",
        "-dane_ee_no_namechecks",
        "-dane_tlsa_domain", f"{hostname}",
    ] + rrdata
    input = b"QUIT\n"
    p = subprocess.Popen(" ".join(sslopts), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, shell=True)
    time.sleep(5.0)
    res = p.communicate(input=input, timeout=1)
    retval = p.wait()
    return retval