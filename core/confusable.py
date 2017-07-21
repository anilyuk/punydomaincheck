from urllib import urlretrieve, urlopen
from copy import deepcopy
import json
from core.common import CONFUSABLE_URL, CONFUSABLE_FILE, BLACKLIST_LETTERS, CHARSET_FILE, WHITELIST_LETTERS
from os import remove

def update_charset(logger, letters_json):
    logger.info("[*] Updating character list")
    # Download confusables.txt
    u = urlopen(CONFUSABLE_URL)
    filesize = int(u.info().getheaders("Content-Length")[0]) / 1000

    logger.info("[*] Downloading {}kb".format(filesize))

    urlretrieve(CONFUSABLE_URL, CONFUSABLE_FILE)

    logger.info("[*] Download completed. Processing now...")

    confusables = open(CONFUSABLE_FILE)

    whitelist_file = open(WHITELIST_LETTERS)
    whitelist_file_json = json.load(whitelist_file)
    whitelist_file.close()

    new_letters_json = deepcopy(letters_json)

    for char_num in range(97, 123):

        new_letters_json[str(chr(char_num))] = []

    # First, get characters from whitelist_letters.json file
    for char_num in range(97, 123):

        for char in whitelist_file_json[str(chr(char_num))]:

            try:

                with_idna = (unicode(char).decode('unicode_escape')).encode("idna")

            except:

                logger.error("[-] Punny Code error for {}".format(char))

                None

            else:

                #if "xn" in with_idna:
                character_array = list(new_letters_json[str(chr(char_num))])
                character_array.append(char)
                new_letters_json[str(chr(char_num))] = character_array

    blacklist_letters = open(BLACKLIST_LETTERS)
    blacklist_letters_json = json.load(blacklist_letters)

    # Read characters from confusable and check if character can be punycode encodede
    for line in confusables:

        for char_num in range(97, 123):

            letter_normal = str(chr(char_num))
            letter_unicode = letters_json[str(chr(char_num))]

            if str(letter_unicode[0]) in line:

                line_spilt = line.split(";")

                if len(line_spilt) > 1:

                    if len(line_spilt[1].rstrip().split(" ")) < 2:

                        line_spilt[0].rstrip()

                        character = str(line_spilt[0]).rstrip()

                        if character not in blacklist_letters_json[chr(char_num)]:

                            if len(character) == 4:

                                character = unicode('\u{}'.format(character))

                            else:

                                character = '\u' + "0" * (8 - len(character)) + character

                            with_idna = ""

                            try:

                                with_idna = (unicode(character).decode('unicode_escape')).encode("idna")

                            except:

                                None

                            else:

                                if "xn" in with_idna:

                                    character_array = list(new_letters_json[letter_normal])
                                    character_array.append(character)
                                    new_letters_json[letter_normal] = character_array

    # for char_num in range(97,123):
    #
    #     print "{} - {}".format(chr(char_num), len(new_letters_json[chr(char_num)]))

    logger.info("[*] Charset successfully created")

    charset = open(CHARSET_FILE, "w")
    json.dump(new_letters_json, charset)
    confusables.close()
    remove(CONFUSABLE_FILE)
    charset.close()