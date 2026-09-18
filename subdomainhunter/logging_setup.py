import logging
from pathlib import Path

LOGGER_NAME = "subdomainhunter"


def setup(level="INFO", log_file=None):
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    logger.propagate = False
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", "%H:%M:%S")
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        logger.addHandler(console)
        if log_file:
            p = Path(log_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(p, encoding="utf-8")
            fh.setFormatter(formatter)
            logger.addHandler(fh)
    return logger
