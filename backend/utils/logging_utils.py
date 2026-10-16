# backend/utils/logging_utils.py
import logging
import sys
import os # Added for potential future file logging

# --- Configuration ---
# Get log level from environment variable if set, otherwise default to INFO
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# --- Logger Setup ---
class AsciiSanitizingFormatter(logging.Formatter):
    """Formatter that strips non-ASCII characters from the final message to avoid Windows console encoding errors."""
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        try:
            return msg.encode('ascii', 'ignore').decode('ascii')
        except Exception:
            return msg


def setup_logger(name: str = "SQL_Injection_Prevention_App",
                 level: str = LOG_LEVEL,
                 log_format: str = LOG_FORMAT,
                 date_format: str = LOG_DATE_FORMAT) -> logging.Logger:
    """
    Configures and returns a logger instance.

    Args:
        name (str): The name for the logger.
        level (str): The logging level (e.g., DEBUG, INFO, WARNING).
        log_format (str): The format string for log messages.
        date_format (str): The format string for dates in log messages.

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(name)

    # Check if logger already has handlers to avoid duplicate logs
    if not logger.handlers:
        logger.setLevel(level) # Set level on the logger itself

        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        # Set level on the handler as well, if you want different handlers to have different verbosity
        console_handler.setLevel(level)

        # Create formatter and add it to the handler
        formatter = AsciiSanitizingFormatter(log_format, datefmt=date_format)
        console_handler.setFormatter(formatter)

        # Add the handler to the logger
        logger.addHandler(console_handler)

        # (Optional file handler block removed)

    # If logger already has handlers, ensure its level is set (in case it was changed)
    # This is less common if you control all logger setup.
    elif logger.level != logging.getLevelName(level):
         logger.setLevel(level)

    return logger

# --- Example Usage (can be removed or kept for testing this module) ---
if __name__ == "__main__":
    # Get a logger instance (default name and level from environment or "INFO")
    default_logger = setup_logger()
    default_logger.debug("This is a debug message (will not show if LOG_LEVEL is INFO).")
    default_logger.info("This is an info message.")
    default_logger.warning("This is a warning message.")
    default_logger.error("This is an error message.")
    default_logger.critical("This is a critical message.")

    print(f"Current default logger level: {logging.getLevelName(default_logger.level)}")

    # Get a logger instance with a custom name and explicitly set level
    custom_logger_debug = setup_logger(name="MyCustomModule", level="DEBUG")
    custom_logger_debug.debug("Custom logger debug message (MyCustomModule).")
    custom_logger_debug.info("Custom logger info message (MyCustomModule).")

    # Test re-getting a logger to ensure handlers aren't duplicated
    another_default_logger_instance = setup_logger()
    another_default_logger_instance.info("Info message from another instance of the default logger (should not have duplicate handlers).")
    print(f"Number of handlers for default_logger: {len(default_logger.handlers)}")
