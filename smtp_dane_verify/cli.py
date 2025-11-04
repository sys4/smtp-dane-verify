# From the RFC: The Certificate Usage field:  Section 2.1.1 of [RFC6698] specifies
# four values: PKIX-TA(0), PKIX-EE(1), DANE-TA(2), and DANE-EE(3).
import logging
import argparse

from smtp_dane_verify.verification import verify

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('main')


def main() -> int:
    # Create the argument parser
    parser = argparse.ArgumentParser(
        prog='danesmtp',
        description="Verify that your DANE records and your SMTP server are configured correctly."
    )

    # Add the -a/--address argument
    parser.add_argument(
        "-a", "--address", type=str, required=False, help="The address parameter"
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
        "-j",
        "--json",
        default=False,
        action='store_true',
        help='Output the verification result as JSON to STDOUT'
    )

    # Add a non-option hostname argument
    parser.add_argument(
        "hostname", type=str, help="The SMTP server hostname (required)"
    )

    # Parse the arguments
    args = parser.parse_args()
    external_resolver = None
    if args.nameserver != '':
        external_resolver = args.nameserver
    result = verify(args.hostname, disable_dnssec=args.no_strict_dnssec, external_resolver=external_resolver, openssl=args.openssl)
    if args.json == True:
        import json
        print(json.dumps(result.dict()))
    else:
        print(result)
    if result.is_valid == True:
        return 0
    else:
        return 1


if __name__ == "__main__":
    retval = main()
    exit(retval)
