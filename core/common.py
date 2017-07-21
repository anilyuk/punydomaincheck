from sys import stdout
from core.logger import LOG_HEADER

CONFUSABLE_URL = "http://www.unicode.org/Public/security/latest/confusables.txt"
CONFUSABLE_FILE = "./misc/confusables.txt"
BLACKLIST_LETTERS = "./misc/blacklist_letters.json"
WHITELIST_LETTERS = "./misc/whitelist_letters.json"
CHARSET_FILE = "./misc/charset.json"
LETTERS_FILE = "./misc/letters.json"
MAX_THREAD_COUNT = 7
OUTPUT_DIR = "./output"


def alternative_filename(args, output_dir):
    return "{}/{}_{}char_alternatives".format(output_dir, args.domain, args.count)


def print_percentage(args, logger, current, total=0, last_percentage=0, header_print=0):

    if total != 0:
        percentage = int((100 * current) / total)
    else:
        percentage = current

    if percentage % 10 == 0 and last_percentage != percentage:

        last_percentage = percentage
        if args.debug:

            logger.info("[*] Processing... {}".format(percentage))

        else:

            if not header_print:
                stdout.write("{}Processing: ".format(LOG_HEADER))
                header_print = True

            string_stdout = ""
            if percentage == 0:

                string_stdout = "{}%".format(percentage)

            elif percentage == 100:

                string_stdout = "...{}%\n".format(percentage)

            else:

                string_stdout = "...{}%".format(percentage)

            stdout.write(string_stdout)

            stdout.flush()

    return last_percentage, header_print