"""
Entry point for running sslspy as a module.

Usage:
    python -m sslspy -f domains.txt
    python -m sslspy -f domains.txt -o results.json -t 10 -w 60 -j 5
    python -m sslspy --help

Options:
    -f, --file FILE          File containing domains to check (one per line) [required]
    -o, --output FILE        Output JSON file for results (default: ssl_check_results.json)
    -t, --timeout SEC        Connection timeout in seconds (default: 5)
    -w, --warning-days DAYS  Days before expiry to trigger warning status (default: 30)
    -j, --workers NUM        Maximum number of concurrent workers (default: 10)
    --no-fancy-ui            Disable the fancy terminal UI
    -h, --help               Show this help message and exit
"""

from sslspy.cli import run_cli

if __name__ == "__main__":
    run_cli()
