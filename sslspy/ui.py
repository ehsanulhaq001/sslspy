"""UI components for the SSLSpy scanner."""

import sys
import time
from typing import List, Dict, Any
from colorama import init, Fore, Style

from sslspy.constants import (
    STATUS_VALID,
    STATUS_WARNING,
    STATUS_EXPIRED,
    STATUS_TIMEOUT,
    STATUS_ERROR,
    MAX_LOG_LINES,
)
from sslspy.utils import pad_line_ansi, strip_ansi_codes

# Initialize colorama (no autoreset so we can control color states explicitly)
init(autoreset=False)


def format_log_line(domain, status, days_left, error_msg):
    """Return a colorized single-line summary of a domain check."""
    if status == STATUS_VALID:
        color = Fore.GREEN
        info = f"{days_left} days left"
    elif status == STATUS_WARNING:
        color = Fore.YELLOW
        info = f"{days_left} days left"
    elif status == STATUS_EXPIRED:
        color = Fore.RED
        info = (
            f"Expired by {-days_left} days"
            if days_left is not None
            else "Already expired"
        )
    elif status == STATUS_TIMEOUT:
        color = Fore.RED
        info = "Timeout"
    else:  # ERROR
        color = Fore.RED
        info = error_msg if error_msg else "Unknown error"

    return f"{color}{domain:<45} {status:<20} {info}{Style.RESET_ALL}"


def draw_boxed_line(line: str, box_width: int) -> str:
    """Helper to wrap a line in ║ ... ║ with correct padding."""
    content_width = box_width - 4
    padded = pad_line_ansi(line, content_width)
    return f"║ {padded} ║"


def draw_ui(
    total_domains,
    completed,
    valid_count,
    warning_count,
    expired_count,
    timeout_count,
    error_count,
    log_lines,
):
    """
    Redraw the terminal interface in place.
    - We maintain a fixed region with stats
    - We show a progress bar (using colored unicode blocks)
    - We keep a scrolling area of the last N log lines
    """
    # Move cursor to top-left and clear screen
    sys.stdout.write("\033[H\033[J")
    box_width = 100

    # Fancy banner at the top
    print(Fore.CYAN + Style.BRIGHT + "╔" + "═" * (box_width - 2) + "╗")
    title = " SSLSpy - SSL/TLS Security Scanner "
    center_space = box_width - 2
    title_stripped = strip_ansi_codes(title)
    if len(title_stripped) > center_space:
        title_stripped = title_stripped[:center_space]
    left_spaces = (center_space - len(title_stripped)) // 2
    right_spaces = center_space - len(title_stripped) - left_spaces
    line = (" " * left_spaces) + title_stripped + (" " * right_spaces)
    print("║" + line + "║")
    print("╚" + "═" * (box_width - 2) + "╝" + Style.RESET_ALL)

    # Calculate progress
    progress = (completed / total_domains) * 100 if total_domains else 0
    bar_width = 70
    filled_length = int(bar_width * progress // 100)

    # Unicode block characters
    filled_bar = "█" * filled_length
    unfilled_bar = "░" * (bar_width - filled_length)

    # Color the filled portion green
    progress_bar = f"{Fore.GREEN}{filled_bar}{Style.RESET_ALL}{unfilled_bar}"

    # Stats lines
    lines_to_print = []
    lines_to_print.append(
        f"Total Domains: {Fore.CYAN}{total_domains}{Style.RESET_ALL}  |  "
        f"Completed: {Fore.CYAN}{completed}{Style.RESET_ALL}/"
        f"{Fore.CYAN}{total_domains}{Style.RESET_ALL}"
    )
    lines_to_print.append(f"Progress: {progress_bar} {progress:5.1f}%")

    # Summaries
    summary_content = (
        f"{Fore.GREEN}VALID: {valid_count:<5}{Style.RESET_ALL}"
        f"{Fore.YELLOW}WARNING: {warning_count:<5}{Style.RESET_ALL}"
        f"{Fore.RED}EXPIRED: {expired_count:<5}{Style.RESET_ALL}"
        f"{Fore.RED}TIMEOUT: {timeout_count:<5}{Style.RESET_ALL}"
        f"{Fore.RED}ERROR: {error_count:<5}{Style.RESET_ALL}"
    )

    # Calculate the visible length of the content (excluding ANSI codes)
    content_length = len(strip_ansi_codes(summary_content))
    # Calculate padding to center the content within the box (box_width - 4 is the content width)
    padding_size = (box_width - 4 - content_length) // 2
    padding = " " * padding_size
    summary_line = f"{padding}{summary_content}"

    lines_to_print.append(summary_line)

    # Print the stats box
    print(
        Fore.CYAN + Style.BRIGHT + "╔" + "═" * (box_width - 2) + "╗" + Style.RESET_ALL
    )
    for l in lines_to_print:
        print(draw_boxed_line(l, box_width))
    print("╚" + "═" * (box_width - 2) + "╝")

    # Recent log area (scrolling)
    print(Fore.CYAN + Style.BRIGHT + "╔" + "═" * (box_width - 2) + "╗")
    title_str = " Recent Checks "
    # Center the title
    title_no_ansi = strip_ansi_codes(title_str)
    if len(title_no_ansi) > (box_width - 2):
        title_no_ansi = title_no_ansi[: (box_width - 2)]
    left_sp = (box_width - 2 - len(title_no_ansi)) // 2
    right_sp = (box_width - 2) - len(title_no_ansi) - left_sp
    line = (" " * left_sp) + title_no_ansi + (" " * right_sp)
    print("║" + line + "║")
    print(draw_boxed_line(f"{Style.RESET_ALL}", box_width))

    # Print each log line in a consistent box format
    for line in log_lines:
        print(draw_boxed_line(line, box_width))

    # If we have fewer lines than MAX_LOG_LINES, fill the space
    empty_lines_needed = MAX_LOG_LINES - len(log_lines)
    for _ in range(empty_lines_needed):
        print(draw_boxed_line("", box_width))
    print("╚" + "═" * (box_width - 2) + "╝" + Style.RESET_ALL)

    sys.stdout.flush()


def print_summary(results, execution_time):
    """Print a final summary after all checks are complete."""
    total = len(results)

    # Count results by status
    status_counts = {
        STATUS_VALID: 0,
        STATUS_WARNING: 0,
        STATUS_EXPIRED: 0,
        STATUS_TIMEOUT: 0,
        STATUS_ERROR: 0,
    }

    for result in results:
        status = result.get("status")
        if status in status_counts:
            status_counts[status] += 1

    print()
    border_line = Fore.CYAN + Style.BRIGHT + ("=" * 100) + Style.RESET_ALL
    print(border_line)
    print("Final Summary:")
    print(
        f"{Fore.GREEN}VALID:{Style.RESET_ALL}   {status_counts[STATUS_VALID]} ("
        + f"{(status_counts[STATUS_VALID]/total)*100 if total else 0:.1f}% )\n"
        f"{Fore.YELLOW}WARNING:{Style.RESET_ALL} {status_counts[STATUS_WARNING]} ("
        + f"{(status_counts[STATUS_WARNING]/total)*100 if total else 0:.1f}% )\n"
        f"{Fore.RED}EXPIRED:{Style.RESET_ALL} {status_counts[STATUS_EXPIRED]} ("
        + f"{(status_counts[STATUS_EXPIRED]/total)*100 if total else 0:.1f}% )\n"
        f"{Fore.RED}TIMEOUT:{Style.RESET_ALL} {status_counts[STATUS_TIMEOUT]} ("
        + f"{(status_counts[STATUS_TIMEOUT]/total)*100 if total else 0:.1f}% )\n"
        f"{Fore.RED}ERROR:{Style.RESET_ALL}   {status_counts[STATUS_ERROR]} ("
        + f"{(status_counts[STATUS_ERROR]/total)*100 if total else 0:.1f}% )"
    )
    print(f"Total Execution Time: {execution_time:.2f} seconds")
    print(border_line)
