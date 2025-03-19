"""Constants used throughout the SSLSpy toolkit."""

# Status codes
STATUS_VALID = "VALID"
STATUS_WARNING = "WARNING"
STATUS_EXPIRED = "EXPIRED"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_ERROR = "ERROR"

# Default settings
DEFAULT_TIMEOUT = 5  # seconds
DEFAULT_WARNING_THRESHOLD = 30  # days
MAX_WORKERS = 10  # maximum concurrent connections

# UI settings
MAX_LOG_LINES = 10

# Shared state flags for controlling execution
EXITING = False
PAUSED = False
