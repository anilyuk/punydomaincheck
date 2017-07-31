# Puny Domain Check v1.0
# Author: Anil YUKSEL, Mustafa Mert KARATAS
# E-mail: anil [ . ] yksel [ @ ] gmail [ . ] com, mmkaratas92 [ @ ] gmail [ . ] com
# URL: https://github.com/anilyuk/punydomaincheck

from logging import DEBUG, INFO, getLogger
from coloredlogs import install
from os import environ

LOG_HEADER = "[*] "


def start_logger(args):
    logger = getLogger("PunyCodeCheck")
    environ["COLOREDLOGS_LOG_FORMAT"] = '%(message)s'

    if args.debug:

        logger.setLevel(DEBUG)
        install(DEBUG, logger=logger)

    else:

        logger.setLevel(INFO)
        install(INFO, logger=logger)

    return logger
