import logging

logger = logging.getLogger("django")


# Centralize log messages for reuse
def log_error(message, exception=None):
    if exception:
        logger.error(f"{message}: {str(exception)}")
    else:
        logger.error(message)


def log_info(message, *args):
    logger.info(message % args)


def log_warning(message):
    logger.warning(message)
