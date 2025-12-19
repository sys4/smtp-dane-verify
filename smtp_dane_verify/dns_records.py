import logging
import traceback
import sys
from typing import List, Optional

import dns.resolver
import dns.rdtypes.ANY.TLSA
from dns.edns import EDECode
from dns.flags import Flag

from smtp_dane_verify.external_resolver import resolve

log = logging.getLogger(__name__)


class TlsaRecordError(Exception):
    pass


class MxRecordError(Exception):
    pass


DNSSEC_BOGUS_ERROR_CODES = [
    EDECode.DNSSEC_BOGUS,
    EDECode.SIGNATURE_EXPIRED,
    EDECode.SIGNATURE_NOT_YET_VALID,
    EDECode.DNSKEY_MISSING,
    EDECode.RRSIGS_MISSING,
    EDECode.NO_ZONE_KEY_BIT_SET,
    EDECode.NSEC_MISSING,
]


def check_dnssec_status(message) -> tuple[bool, str]:
    """
    Helper function for resolve().
    """
    for error in message.extended_errors():
        if error.code in DNSSEC_BOGUS_ERROR_CODES:
            return (False, f'bogus, EDE error code {error.code}')
    if message.flags & Flag.AD:
        return (True, 'secure')
    else:
        return (False, 'insecure, AD flag not set or resolver has DNSSEC disabled.')


def get_tlsa_record(hostname: str, external_resolver: Optional[str]=None) -> tuple[dns.resolver.Answer, bool, str]:
    query = f"_25._tcp.{hostname}"
    try:
        if external_resolver is None:
            # Perform the DNS query for the TLSA record
            tlsa_records = resolve(None, query, "TLSA")
            log.debug("Using default resolver.")
        else:
            tlsa_records = resolve(external_resolver, query, "TLSA")
        dnssec_status, dnssec_message = check_dnssec_status(tlsa_records.response)
        return tlsa_records, dnssec_status, dnssec_message

    except dns.resolver.NoAnswer:
        raise TlsaRecordError(f"No TLSA record found for {query}")
    except dns.resolver.NXDOMAIN:
        raise TlsaRecordError(f"Domain {query} does not exist")
    except dns.resolver.Timeout:
        raise TlsaRecordError(f"Timeout while querying {query}")
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        raise TlsaRecordError(f"An error occurred: {e}")


def get_mx_records(domain: str, external_resolver: Optional[str]=None) -> tuple[List[str], bool, str]:
    try:
        if external_resolver is None:
            # Perform the DNS query for the TLSA record
            mx_record = resolve(None, domain, "MX")
            mailserver_set = mx_record.rrset
            log.debug("Using default resolver.")
        else:
            mx_record = resolve(external_resolver, domain, "MX")
            mailserver_set = mx_record.rrset

        dnssec_status, dnssec_message = check_dnssec_status(mx_record.response)

        mailservers = []
        for i in mailserver_set:
            mx_record = f'{i.exchange}'
            mailservers.append(mx_record)

        return mailservers, dnssec_status, dnssec_message
 
    except dns.resolver.NoAnswer:
        raise MxRecordError(f"No MX records found for {domain}")
    except dns.resolver.NXDOMAIN:
        raise MxRecordError(f"Domain {domain} does not exist")
    except dns.resolver.Timeout:
        raise MxRecordError(f"Timeout while querying {domain}")
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        raise MxRecordError(f"An error occurred: {e}")


def filter_tlsa_resource_records(
    answers: List[dns.rdtypes.ANY.TLSA.TLSA],
    usages: List[int] = [2, 3],
    selectors: List[int] = [0, 1],
    matching_types: List[int] = [0, 1, 2],
) -> List[dns.rdtypes.ANY.TLSA.TLSA]:
    """
    Filter the answers from get_tlsa_record, only use the ones we need.
    """
    filtered_answers = []
    for answer in answers:
        if not answer.usage in usages:
            continue
        if not answer.selector in selectors:
            continue
        if not answer.mtype in matching_types:
            continue
        # All the conditions are met, add to answers
        filtered_answers.append(answer)
    return filtered_answers
