#from logging import getLogger, Formatter, StreamHandler, DEBUG, INFO
from logging import Formatter, DEBUG, INFO, StreamHandler, getLogger
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

    #formatter = ColoredFormatter('%(log_color)s%(message)s')
    #ch = StreamHandler()
    #ch.setFormatter(formatter)
    #logger.addHandler(ch)
    return logger
