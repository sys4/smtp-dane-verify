import dns.resolver


class TlsaRecordError(Exception):
    pass


def get_tlsa_record(hostname):
    query = f'_25._tcp.{hostname}'
    try:
        # Perform the DNS query for the TLSA record
        answers = dns.resolver.resolve(query, 'TLSA')
        # Extract and return the TLSA records
        tlsa_records = [answer.to_text() for answer in answers]
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
