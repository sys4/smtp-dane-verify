# From the RFC: The Certificate Usage field:  Section 2.1.1 of [RFC6698] specifies
# four values: PKIX-TA(0), PKIX-EE(1), DANE-TA(2), and DANE-EE(3).

import argparse

def main():
    # Create the argument parser
    parser = argparse.ArgumentParser(description='Process some parameters.')

    # Add the -a/--address argument
    parser.add_argument('-a', '--address', type=str, required=False, help='The address parameter')

    # Add the -u/--usages argument with a default value of '2,3'
    parser.add_argument('-u', '--usages', type=str, default='2,3', help='The usages parameter (default: 2,3)')

    # Add a non-option hostname argument
    parser.add_argument('hostname', type=str, help='The SMTP server hostname (required)')

    # Parse the arguments
    args = parser.parse_args()

    # Print the parsed arguments
    print(f'Address: {args.address}')
    print(f'Usages: {args.usages}')
    print(f'Hostname: {args.hostname}')

if __name__ == '__main__':
    main()