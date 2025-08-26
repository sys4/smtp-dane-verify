#!/usr/bin/env bash

set -e

# Function to display usage information
usage() {
    echo "Usage: $0 [--port PORT]"
    echo "  -p PORT      The port to run the application on (default:3000)"
    # echo "  -d DEBUG_MODE Enable debug mode (default: false)"
    exit 1
}

# Default values
PORT=3000
DEBUG_MODE=false

# Parse command-line arguments
while getopts ":p:d" opt; do
    case ${opt} in
        p )
            PORT=$OPTARG
            ;;
        d )
            DEBUG_MODE=true
            ;;
        \? )
            echo "Invalid option: $OPTARG" 1>&2
            usage
            ;;
        : )
            echo "Invalid option: $OPTARG requires an argument" 1>&2
            usage
            ;;
    esac
done
shift $((OPTIND -1))

# Print the configuration
echo "Running application on port $PORT"
if [ "$DEBUG_MODE" = true ]; then
    echo "Debug mode is enabled"
else
    echo "Debug mode is disabled"
fi

/app/.venv/bin/python3  -m uvicorn --host 0.0.0.0 --port "$PORT" smtp_dane_verify.api:app