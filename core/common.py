# Puny Domain Check v1.0
# Author: Anil YUKSEL, Mustafa Mert KARATAS
# E-mail: anil [ . ] yksel [ @ ] gmail [ . ] com, mmkaratas92 [ @ ] gmail [ . ] com
# URL: https://github.com/anilyuk/punydomaincheck

from sys import stdout, platform
from core.logger import LOG_HEADER

VERSION = "1.0.3"
CONFUSABLE_URL = "http://www.unicode.org/Public/security/latest/confusables.txt"
CONFUSABLE_FILE = "./misc/confusables.txt"
BLACKLIST_LETTERS = "./misc/blacklist_letters.json"
WHITELIST_LETTERS = "./misc/whitelist_letters.json"
CHARSET_FILE = "./misc/charset.json"
LETTERS_FILE = "./misc/letters.json"
MAX_THREAD_COUNT = 7
OUTPUT_DIR = "./output"
GEOLOCATION_WEBSITE = "http://freegeoip.net/json"
### YOUR VIRUSTOTAL API KEYs
VT_APIKEY_LIST = []

BANNER = ''' _ __  _   _ _ __  _   _  ___| |__   ___  ___| | __
| '_ \| | | | '_ \| | | |/ __| '_ \ / _ \/ __| |/ /
| |_) | |_| | | | | |_| | (__| | | |  __/ (__|   <
| .__/ \__,_|_| |_|\__, |\___|_| |_|\___|\___|_|\_\\
|_|                |___/                                {}
'''.format(VERSION)


# Set console colors
if platform != 'win32' and stdout.isatty():
    YEL = '\x1b[33m'
    MAG = '\x1b[35m'
    BLU = '\x1b[34m'
    GRE = '\x1b[32m'
    RED = '\x1b[31m'
    RST = '\x1b[39m'
    CYA = '\x1b[36m'


else:
    YEL = ''
    MAG = ''
    GRE = ''
    RED = ''
    BLU = ''
    CYA = ''
    RST = ''


def alternative_filename(args, output_dir):
    return "{}/{}_{}char_alternatives".format(output_dir, args.domain, args.count)


def print_percentage(args, logger, current, total=0, last_percentage=0, header_print=False):
    if total != 0:
        percentage = int((100 * current) / total)
    else:
        percentage = current

    if not header_print and not args.debug:
        stdout.write("{}Processing: {}0%".format(LOG_HEADER, BLU))
        header_print = True
        stdout.flush()

    if percentage % 10 == 0 and last_percentage != percentage and percentage != 0:

        last_percentage = percentage
        if args.debug:

            logger.info("[*] Processing... {}{}{}".format(BLU, percentage, RST))

        else:

            if percentage == 100:

                string_stdout = "...{}%{}\n".format(percentage, RST)

            else:

                string_stdout = "...{}%".format(percentage)

            stdout.write(string_stdout)

            stdout.flush()

    return last_percentage, header_print
