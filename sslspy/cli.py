"""Command-line interface for the SSLSpy toolkit."""

import os
import sys
import time
import signal
import argparse
import traceback
from typing import List, Dict, Any
from colorama import init, Fore, Style

from sslspy.constants import (
    STATUS_VALID,
    STATUS_WARNING,
    STATUS_EXPIRED,
    STATUS_TIMEOUT,
    STATUS_ERROR,
    DEFAULT_TIMEOUT,
    DEFAULT_WARNING_THRESHOLD,
    MAX_WORKERS,
    EXITING,
    PAUSED,
)
from sslspy.checker import check_domains
from sslspy.ui import draw_ui, format_log_line, print_summary
from sslspy.utils import read_domains, save_results_to_json

# Global flag to track if we are exiting
exiting = False
paused = False


def signal_handler(sig, frame):
    """Handle SIGINT (Ctrl+C) by pausing and asking for confirmation before exiting."""
    global paused

    # Import and modify the shared state
    import sslspy.constants as constants

    # If already exiting, force immediate exit on second CTRL+C
    if constants.EXITING:
        print(f"\n{Fore.RED}Forced exit.{Style.RESET_ALL}")
        os._exit(1)

    # If already paused, treat second CTRL+C as confirmation to exit
    if constants.PAUSED:
        constants.EXITING = True
        print(f"\n{Fore.RED}Received second interrupt. Exiting...{Style.RESET_ALL}")
        os._exit(1)

    # First CTRL+C: pause execution and ask for confirmation
    constants.PAUSED = True
    paused = True

    # Show cursor for user input
    sys.stdout.write("\033[?25h")

    print(f"\n{Fore.YELLOW}Process paused.{Style.RESET_ALL}")
    try:
        response = input(f"{Fore.YELLOW}Do you want to exit? (y/n): {Style.RESET_ALL}")
        if response.lower() in ["y", "yes"]:
            constants.EXITING = True
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            os._exit(1)
        else:
            constants.PAUSED = False
            paused = False
            print(f"{Fore.GREEN}Resuming...{Style.RESET_ALL}")
            # Hide cursor again if UI is fancy
            if not parse_args().no_fancy_ui:
                sys.stdout.write("\033[?25l")
    except KeyboardInterrupt:
        # If they press CTRL+C during the prompt, exit
        constants.EXITING = True
        print(f"\n{Fore.RED}Exiting...{Style.RESET_ALL}")
        os._exit(1)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="SSLSpy: A comprehensive SSL/TLS security scanner."
    )

    parser.add_argument(
        "-f",
        "--file",
        help="File containing domains to check (one per line)",
        required=True,
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output JSON file for results",
        default="sslspy_results.json",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        help="Connection timeout in seconds",
        type=int,
        default=DEFAULT_TIMEOUT,
    )

    parser.add_argument(
        "-w",
        "--warning-days",
        help="Days before expiry to trigger warning status",
        type=int,
        default=DEFAULT_WARNING_THRESHOLD,
    )

    parser.add_argument(
        "-j",
        "--workers",
        help="Maximum number of concurrent workers",
        type=int,
        default=MAX_WORKERS,
    )

    parser.add_argument(
        "--no-fancy-ui", help="Disable the fancy terminal UI", action="store_true"
    )

    return parser.parse_args()


def run_cli():
    """Main CLI entry point."""
    global paused

    try:
        args = parse_args()
    except SystemExit:
        # Show cursor before exiting if it was hidden
        sys.stdout.write("\033[?25h")
        print(f"\n{Fore.YELLOW}Usage example: sslspy -f domains.txt{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Use -h or --help for more information.{Style.RESET_ALL}")
        sys.exit(1)

    # Initialize colorama
    init(autoreset=False)

    # Setup signal handler for CTRL+C
    signal.signal(signal.SIGINT, signal_handler)

    # Make sure cursor is visible on exit
    cursor_shown = False

    try:
        # Hide cursor for nicer UI updates
        if not args.no_fancy_ui:
            sys.stdout.write("\033[?25l")

        # Read domains from file
        try:
            domains = read_domains(args.file)
        except FileNotFoundError as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            print(
                f"{Fore.YELLOW}Please provide a valid domains file with the -f option.{Style.RESET_ALL}"
            )
            if not args.no_fancy_ui:
                sys.stdout.write("\033[?25h")  # show cursor again
            sys.exit(1)

        total_domains = len(domains)
        if total_domains == 0:
            print(f"{Fore.RED}No domains found in {args.file}.{Style.RESET_ALL}")
            if not args.no_fancy_ui:
                sys.stdout.write("\033[?25h")  # show cursor again
            sys.exit(1)

        # Statistics for UI
        stats = {
            "valid": 0,
            "warning": 0,
            "expired": 0,
            "timeout": 0,
            "error": 0,
            "completed": 0,
            "log_lines": [],
        }

        def ui_callback(result, completed, total):
            """Callback function to update UI as each domain completes."""
            # Check if we're exiting before proceeding
            import sslspy.constants as constants

            if constants.EXITING:
                return

            domain = result["domain"]
            status = result["status"]
            days_left = result["days_left"]
            error_msg = result["error_msg"]

            # Update counters
            if status == STATUS_VALID:
                stats["valid"] += 1
            elif status == STATUS_WARNING:
                stats["warning"] += 1
            elif status == STATUS_EXPIRED:
                stats["expired"] += 1
            elif status == STATUS_TIMEOUT:
                stats["timeout"] += 1
            elif status == STATUS_ERROR:
                stats["error"] += 1
            else:  # ERROR
                stats["error"] += 1

            stats["completed"] = completed

            # Log line
            line = format_log_line(domain, status, days_left, error_msg)
            stats["log_lines"].append(line)
            if len(stats["log_lines"]) > 10:
                # Keep only the last 10 lines
                stats["log_lines"] = stats["log_lines"][-10:]

            if args.no_fancy_ui:
                # Simple progress output
                if completed == 1 or completed % 5 == 0 or completed == total:
                    progress = (completed / total) * 100
                    print(f"\rProgress: {progress:.1f}% ({completed}/{total})", end="")
                print(f"\n{line}")
            else:
                # Fancy UI update
                draw_ui(
                    total_domains,
                    completed,
                    stats["valid"],
                    stats["warning"],
                    stats["expired"],
                    stats["timeout"],
                    stats["error"],
                    stats["log_lines"],
                )

        # Perform the checks
        start_time = time.time()
        results = check_domains(
            domains,
            timeout=args.timeout,
            warning_threshold=args.warning_days,
            max_workers=args.workers,
            callback=ui_callback,
        )
        end_time = time.time()
        execution_time = end_time - start_time

        # Print final summary
        print_summary(results, execution_time)

        # Save to JSON
        save_results_to_json(results, args.output)
        print(f"Detailed results saved to {args.output}")

        # Show cursor again before exiting normally
        if not args.no_fancy_ui and not cursor_shown:
            sys.stdout.write("\033[?25h")
            cursor_shown = True

    except KeyboardInterrupt:
        # Graceful exit should be handled by signal handler
        # This is just a fallback
        if not args.no_fancy_ui and not cursor_shown:
            sys.stdout.write("\033[?25h")
            cursor_shown = True
        if not exiting:  # Only print if signal handler hasn't already
            print(f"\n{Fore.RED}Interrupted by user. Exiting...{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        if not args.no_fancy_ui and not cursor_shown:
            sys.stdout.write("\033[?25h")
            cursor_shown = True
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Always show cursor again
        if not args.no_fancy_ui and not cursor_shown:
            sys.stdout.write("\033[?25h")
