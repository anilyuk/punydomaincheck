import json
from core.exceptions import CharSetException, AlternativesExists, NoAlternativesFound
from itertools import product, combinations
from datetime import datetime
from core.common import LETTERS_FILE, CHARSET_FILE, alternative_filename, print_percentage
from os.path import isfile

import sys


def load_letters():
    json_data = open(LETTERS_FILE)
    letters_json = json.load(json_data)
    json_data.close()

    return letters_json


def load_charset():
    try:

        charset = open(CHARSET_FILE)
        charset_json = json.load(charset)
        charset.close()

    except:

        raise CharSetException("CharSet not found")

    return charset_json


def calculate_alternative_count(domain_name, charset_json, combination):
    count = 1
    total_count = 0

    for positions in combination:

        for i in range(0, len(domain_name)):

            if i in positions:
                count = count * len(charset_json[domain_name[i]])

        total_count += count
        count = 1
    if total_count == 0:
        raise NoAlternativesFound
    return total_count


def create_alternatives(args, charset_json, logger, output_dir):
    alternatives_filename = alternative_filename(args=args, output_dir=output_dir)

    domain_name = str(args.domain).split(".")[0]

    combination = list(combinations(range(0, len(domain_name)), int(args.count)))

    total_alternative_count = calculate_alternative_count(domain_name, charset_json, combination)

    alternative_count = 0
    last_percentage = 1
    header_print = False

    logger.info("[*] {} alternatives found for {}".format(total_alternative_count, domain_name))

    if isfile(alternatives_filename) and not args.force:
        raise AlternativesExists

    alternatives_file = open(alternatives_filename, 'w')

    logger.info("[*] Creating idna domain names for {}".format(domain_name))

    logger.info("[*] {}".format(datetime.now()))

    for positions in combination:

        character_alternative_list = []

        for i in range(0, len(domain_name)):

            if i in positions:

                try:

                    character_alternative_list.append(charset_json[domain_name[i]])

                except KeyError, k:

                    character_alternative_list.append(domain_name[i])

            else:

                character_alternative_list.append(domain_name[i])

        all_alternatives_product = (product(*character_alternative_list))

        for item in all_alternatives_product:

            temp_str = "".join(item)

            temp_str_unicode = (unicode(temp_str).decode('unicode_escape'))
            try:

                with_idna = temp_str_unicode.encode('idna')
                #if "xn" not in with_idna:
                #print "{} - {}".format(temp_str, with_idna)

            except:

                logger.error("[-] PunyCode problem: {}".format(temp_str))

            else:

                alternatives_file.write("{}\n".format(with_idna))

                alternative_count += 1

            last_percentage, header_print = print_percentage(args, logger, alternative_count, total_alternative_count,
                                                             last_percentage, header_print)

    alternatives_file.close()
    logger.info("[*] {}".format(datetime.now()))
