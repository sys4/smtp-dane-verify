from typing import List

import dns.resolver
import dns.rdtypes.ANY.TLSA


class TlsaRecordError(Exception):
    pass


def get_tlsa_record(hostname):
    query = f"_25._tcp.{hostname}"
    try:
        # Perform the DNS query for the TLSA record
        tlsa_records = dns.resolver.resolve(query, "TLSA")
        # Extract and return the TLSA records
        return tlsa_records
    except dns.resolver.NoAnswer:
        raise TlsaRecordError(f"No TLSA record found for {query}")
    except dns.resolver.NXDOMAIN:
        raise TlsaRecordError(f"Domain {query} does not exist")
    except dns.resolver.Timeout:
        raise TlsaRecordError(f"Timeout while querying {query}")
    except Exception as e:
        raise TlsaRecordError(f"An error occurred: {e}")


def filter_tlsa_resource_records(
    answers: List[dns.rdtypes.ANY.TLSA.TLSA],
    usages: List[int] = [2, 3],
    selectors: List[int] = [0, 1],
    matching_types: List[int] = [0, 1, 2],
) -> List[dns.rdtypes.ANY.TLSA.TLSA]:
    """
    Filter the answers from get_tlsa_record, only use the
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
