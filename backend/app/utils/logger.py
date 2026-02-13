import logging
import sys

from app.config import settings


def setup_logger(name: str) -> logging.Logger:
    """
    Setup application logger.
    
    Args:
        name: Logger name
        
    Returns:
        Configured logger instance
    """

    logger = logging.getLogger(name)
    
    logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger


logger = setup_logger('app')
