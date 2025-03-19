"""Utility functions for SSLSpy."""

import os
import json
import re
from typing import List, Dict, Any


def read_domains(filepath: str) -> List[str]:
    """
    Read a list of domains from a file, one domain per line.

    Args:
        filepath: Path to the file containing domains

    Returns:
        List of domain strings
    """
    with open(filepath, "r") as f:
        # Strip whitespace and filter out empty lines and comments
        domains = [
            line.strip()
            for line in f
            if line.strip() and not line.strip().startswith("#")
        ]
    return domains


def save_results_to_json(results: List[Dict[str, Any]], filepath: str) -> None:
    """
    Save check results to a JSON file.

    Args:
        results: List of result dictionaries
        filepath: Output file path
    """
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    # ANSI color code pattern
    ansi_pattern = re.compile(r"\033\[\d+(?:;\d+)*m")
    return ansi_pattern.sub("", text)


def pad_line_ansi(line: str, width: int) -> str:
    """
    Pad a line to specified width, accounting for ANSI color codes.

    Args:
        line: Text that may include ANSI color codes
        width: Target visible character width

    Returns:
        Padded string that will display as exactly 'width' characters
    """
    stripped = strip_ansi_codes(line)
    visible_length = len(stripped)

    if visible_length > width:
        # Truncate, keeping ANSI codes
        visible_chars = 0
        result = ""
        for i, char in enumerate(line):
            if char == "\033":
                # Capture the entire ANSI sequence
                j = i
                while j < len(line) and line[j] != "m":
                    j += 1
                if j < len(line):
                    result += line[i : j + 1]
                    i = j  # Skip ahead
            else:
                result += char
                visible_chars += 1
                if visible_chars >= width:
                    break
        return result
    else:
        # Pad
        padding = " " * (width - visible_length)
        return line + padding
