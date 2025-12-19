import logging
import socket
from typing import Optional

import dns.name
from dns.rrset import RRset
from dns.flags import Flag, EDNSFlag
from dns.rdatatype import RdataType
from dns.resolver import Resolver, NXDOMAIN, NoAnswer, Answer
from dns.edns import EDECode

log = logging.getLogger(__name__)

# Global variable
_resolver = None

RESOLVER_TIMEOUT = 10.0   # seconds as float


def create_resolver(resolver_addr: Optional[str] = None) -> Resolver:
    
    if resolver_addr is not None:
        resolver = Resolver(configure=False)
        resolver.nameservers = [socket.gethostbyname(resolver_addr)]
        log.info("Using user-specified nameserver: %s" ', '.join(resolver.nameservers))
    else:
        resolver = Resolver()
        log.info("NAMESERVER not set, using default nameservers: %s" % ', '.join(resolver.nameservers))
    resolver.edns = True
    # resolver.flags = Flag.CD   # disabled, this flag causes problems with at least 1.1.1.1 and 8.8.8.8
    resolver.ednsflags = EDNSFlag.DO
    resolver.flags = dns.flags.AD | dns.flags.RD
    resolver.lifetime = RESOLVER_TIMEOUT
    return resolver


def get_resolver(resolver_addr: Optional[str] = None) -> Resolver:
    # Resolver considered thread safe once configured
    global _resolver
    if not _resolver:
        _resolver = create_resolver(resolver_addr)
    return _resolver


def resolve(resolver_addr: str, qname: str, rr_type: str, raise_on_no_answer=True) -> Answer:
    log.debug("Resolving `%s` via %s" % (qname, resolver_addr))
    answer = get_resolver(resolver_addr)\
        .resolve(dns.name.from_text(qname), rr_type, raise_on_no_answer=raise_on_no_answer)
    return answer
