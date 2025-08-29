# From the RFC: The Certificate Usage field:  Section 2.1.1 of [RFC6698] specifies
# four values: PKIX-TA(0), PKIX-EE(1), DANE-TA(2), and DANE-EE(3).

import argparse

from smtp_dane_verify.dns_records import get_tlsa_record, filter_tlsa_resource_records
from smtp_dane_verify.verification import verify, verify_tlsa_resource_record


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
    result = verify(args.hostname, openssl=args.openssl)
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
