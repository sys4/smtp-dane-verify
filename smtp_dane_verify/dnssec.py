import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype


class DNSSECError(Exception):
    pass


def query_dnssec(hostname: str) -> bool:
    # get nameservers for target 
    domain = None
    response = dns.resolver.query(
        f'{hostname}.',
        dns.rdatatype.NS,
        raise_on_no_answer=False,
    )
    if response.rrset is None:
        domain = str(response.response.authority[0].name)
        response = dns.resolver.query(
            domain,
            dns.rdatatype.NS,
            raise_on_no_answer=False,
        )
    else:
        domain = f"{hostname}."

    # we'll use the first nameserver in this example
    nsname = response.rrset[0].to_text() # name
    response = dns.resolver.query(nsname, dns.rdatatype.A)
    nsaddr = response.rrset[0].to_text() # IPv4

    # get DNSKEY for zone
    request = dns.message.make_query(
        domain,
        dns.rdatatype.DNSKEY,
        want_dnssec=True
    )

    # send the query
    response = dns.query.udp(request, nsaddr, 10.0)
    if response.rcode() != 0:
        # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)
        raise DNSSECError('DNS server error or no DNSKEY record found (UDP step).')

    # If UDP does not give us a result, try again with TCP
    answer = response.answer
    if len(answer) == 0:
        response = dns.query.tcp(request, nsaddr, 10.0)
        if response.rcode() != 0:
            # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)
            raise DNSSECError("DNS server error or no DNSKEY record found (TCP step).")
        
    # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
    answer = response.answer
    if len(answer) != 2:
        # SOMETHING WENT WRONG
        raise DNSSECError("DNSKEY query did not resolve to [DNSKEY, RRSIG(DNSKEY)].")
    
    # the DNSKEY should be self signed, validate it
    #name = dns.name.from_text(f'_25._tcp.{hostname}.')
    name = dns.name.from_text(f'{domain}.')
    try:
        rrset = answer[0]
        rrsigset = answer[1]
        keys = {name:answer[0]}
        dns.dnssec.validate(rrset, rrsigset, keys)
    except dns.dnssec.ValidationFailure as err:
        # BE SUSPICIOUS
        raise DNSSECError(f"DNSSECValidationFailure for `{domain}`: {err}")
    
    request = dns.message.make_query(
        domain,
        dns.rdatatype.DNSKEY,
        want_dnssec=True
    )

    # Now that we know that the domain is signed, do the actual request
    tlsa_request = dns.message.make_query(
        f'_25._tcp.{hostname}',
        dns.rdatatype.TLSA,
        want_dnssec=True
    )
    tlsa_response = dns.query.udp(tlsa_request, nsaddr, 10.0)
    if response.rcode() != 0:
        # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)
        raise DNSSECError('DNS server error or no DNSKEY record found (UDP step).')

    # If UDP does not give us a result, try again with TCP
    tlsa_answer = tlsa_response.answer
    if len(answer) == 0:
        tlsa_response = dns.query.tcp(tlsa_request, nsaddr, 10.0)
        if response.rcode() != 0:
            # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)
            raise DNSSECError("DNS server error or no DNSKEY record found (TCP step).")

    # the TLSA-RR should be signed by the same keys
    name = dns.name.from_text(f'_25._tcp.{hostname}.')
    try:
        rrset = tlsa_answer[0]
        rrsigset = tlsa_answer[1]
        dns.dnssec.validate(rrset, rrsigset, keys)
    except dns.dnssec.ValidationFailure as err:
        # Something suspicious is happening
        raise DNSSECError(f"DNSSECValidationFailure for `_25._tcp.{hostname}`: {err}")
    
    return True