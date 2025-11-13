# From the RFC: The Certificate Usage field:  Section 2.1.1 of [RFC6698] specifies
# four values: PKIX-TA(0), PKIX-EE(1), DANE-TA(2), and DANE-EE(3).
import logging
import argparse
from smtp_dane_verify.verification import \
    VerificationResult, DomainVerificationResult, \
    verify, verify_domain_servers


def format_results(results: VerificationResult|DomainVerificationResult, format: str):
    """
    Formats the results and prints to STDOUT.
    """
    if format == 'json':
        print(results.model_dump_json())
    elif format == 'text':
        # Default format is 'text'
        print(results)
    else:
        log = logging.getLogger('main')
        log.error('Unknown format "%s" specified.' % format)


def main() -> int:
    # Create the argument parser
    parser = argparse.ArgumentParser(
        prog='danesmtp',
        description="Verify that your DANE records and your SMTP server are configured correctly.",
        add_help=False
    )
    # Add the --help option back
    parser.add_argument(
        '--help',
        action='store_true',
        help='show this help message and exit'
    )

    parser.add_argument(
        '-v',
        '--verbose',
        default=False,
        action='store_true',
        help='Enable more verbose logging (for debugging purposes).'
    )

    # Add the -u/--usages argument with a default value of '2,3'
    parser.add_argument(
        "-u",
        "--usages",
        type=str,
        default="2,3",
        help="The usages parameter (default: 2,3)",
    )

    # Allow to set the OpenSSL binary path
    parser.add_argument(
        "-o",
        "--openssl",
        type=str,
        default="openssl",
        help='Path to the `openssl` binary, default: "openssl"',
    )

    parser.add_argument(
        "-n",
        "--nameserver",
        type=str,
        default="",
        help='Optional IP address of an external nameserver, by default the default resolver will be used.',
    )

    parser.add_argument(
        "--no-strict-dnssec",
        default=False,
        action='store_true',
        help='Relax on the DNSSEC verification of the TLSA records.'
    )

    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default='text',
        help='Select the output format. Available formats: json, text',
    )

    # Add a non-option hostname argument
    parser.add_argument(
        "-h", 
        "--hostname",
        "--host",
        type=str,
        default=None,
        help="The SMTP server hostname to be checked (either --hostname or --domain  is required)"
    )

    # Add the -a/--address argument
    parser.add_argument(
        "-a",
        "--address", 
        type=str, 
        required=False, 
        help="Overwrite the address of the mail server, only to be used with --hostname."
    )

    # Add a non-option hostname argument
    parser.add_argument(
        "-d",
        "--domain",
        type=str,
        default=None,
        help="The domain to be checked (either --hostname or --domain  is required)"
    )

    # Parse the arguments
    args = parser.parse_args()
    log = None

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
        log = logging.getLogger('main')
        log.debug('DEBUG logging enabled.')
    else:
        logging.basicConfig(level=logging.INFO)
        log = logging.getLogger('main')
        log.debug('DEBUG logging enabled.')

    if args.help:
        parser.print_help()
        return 128

    if args.hostname is None and args.domain is None:
        parser.print_usage()
        log.error("You must specify either `--hostname/-h` or `--domain/-d` parameters.")
        return 1

    external_resolver = None
    if args.nameserver != '':
        external_resolver = args.nameserver

    if args.hostname is not None:
        result = verify(args.hostname, disable_dnssec=args.no_strict_dnssec, external_resolver=external_resolver, openssl=args.openssl)
        format_results(result, args.format)
        if result.host_dane_verified == True:
            return 0
        else:
            return 1
    elif args.domain is not None:
        result = verify_domain_servers(args.domain, disable_dnssec=args.no_strict_dnssec, external_resolver=external_resolver, openssl=args.openssl)
        format_results(result, args.format)
        if result.all_hosts_dane_verified == True:
            return 0
        else:
            return 1


if __name__ == "__main__":
    retval = main()
    exit(retval)
