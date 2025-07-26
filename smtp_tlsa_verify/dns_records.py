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
        print(f"No TLSA record found for {query}")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"Domain {query} does not exist")
        return []
    except dns.resolver.Timeout:
        print(f"Timeout while querying {query}")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []


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
