from argparse import ArgumentParser, RawTextHelpFormatter
from sys import exit, stdout

from core.creator import *
from core.exceptions import CharSetException, AlternativesExists
from core.logger import start_logger
from core.confusable import update_charset
from core.domain import load_domainnames, dns_client
from core.common import print_percentage, OUTPUT_DIR
from time import sleep
from Queue import Queue
from os.path import getsize
from os import remove, mkdir, stat


def arg_parser():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("-d", "--domain", default="havelsan", help="Domain without prefix and suffix. (google)")
    parser.add_argument("-s", "--suffix", default="com", help="Suffix to check alternative domain names. (.com, .net)")
    parser.add_argument("-u", "--update", action="store_true", default=False, help="Update character set")
    parser.add_argument("--debug", action="store_true", default=False, help="Enable debug logging")
    parser.add_argument("-c", "--count", default="all", help="Character count to change with punycode alternative")
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Force to calculate alternative domain names")
    parser.add_argument("-t", "--thread", default=10, help="Thread count")
    parser.add_argument("-os", "--original_suffix", default="com.tr",
                        help="Original domain to check for phisihing")
    parser.add_argument("-op", "--original_port", default=80, help="Original port to check for phisihing")

    return parser.parse_args()


# letters_json = load_letters()

def punyDomainCheck(args):
    logger = start_logger(args)

    letters_json = load_letters()

    try:

        charset_json = load_charset()

    except CharSetException:

        if (not args.update):
            update_charset(logger, letters_json)

    if args.update:
        update_charset(logger, letters_json)

    elif int(args.count) < len(args.domain):

        try:

            stat(OUTPUT_DIR)

        except:

            mkdir(OUTPUT_DIR)

        output_dir = "{}/{}".format(OUTPUT_DIR, args.domain)

        try:

            stat(output_dir)

        except:

            mkdir(output_dir)

        try:
            create_alternatives(args=args, charset_json=charset_json, logger=logger, output_dir=output_dir)

        except AlternativesExists:

            logger.info("[*] Alternatives already created. Skipping to next phase..")
        except NoAlternativesFound:
            logger.info("[*] No alternatives found for domain \"{}\".".format(args.domain))
            exit()

        domain_name_list = load_domainnames(args=args, output_dir=output_dir)
        dns_thread_list = []
        threads_queue = []
        thread_count = 0
        logger.info("[*] Every thread will resolve {} names".format(str(len(domain_name_list[0]))))
        logger.info("[*] {}".format(datetime.now()))

        for list in domain_name_list:

            if len(list) > 0:
                thread_queue = Queue()
                threads_queue.append(thread_queue)

                dns_thread = dns_client(args=args, logger=logger, domain_list=list, output_queue=thread_queue,
                                        thread_name=str(thread_count))
                dns_thread.daemon = True
                dns_thread.start()
                dns_thread_list.append(dns_thread)

                thread_count += 1

        logger.info("[*] DNS Client thread started. Thread count: {}".format(len(dns_thread_list)))

        dns_client_completed = False
        query_result = []

        last_percentage = 1
        header_print = False

        while not dns_client_completed:

            sleep(0.001)

            for queue in threads_queue:

                if not queue.empty():
                    query_result.append(queue.get())

            if len(query_result) == int(thread_count):
                dns_client_completed = True

            total_percentage = 0

            for dns_thread in dns_thread_list:
                total_percentage += dns_thread.get_percentage()

            total_percentage = total_percentage / int(thread_count)

            last_percentage, header_print = print_percentage(args, logger, total_percentage,
                                                             last_percentage=last_percentage,
                                                             header_print=header_print)

        dns_file_name = "{}/{}_dns".format(output_dir, args.domain)
        dns_file_content = []
        dns_file_new_created = True
        try:
            with open(dns_file_name, "r") as file:
                dns_file_content = file.readlines()

        except:
            pass

        else:
            dns_file_new_created = False

        print_header = True

        dns_file = open(dns_file_name, 'a')

        for results in query_result:

            for result in results:

                if len(result.get_domain_name()) > 1:

                    whois_email = ""
                    whois_name = ""
                    whois_organization = ""
                    whois_result = result.get_whois_result()

                    if whois_result:

                        if "contacts" in whois_result:

                            whois_contacts = whois_result["contacts"]

                            if "admin" in whois_contacts:

                                whois_admin = whois_contacts["admin"]

                                if whois_admin:

                                    if "email" in whois_admin: whois_email = whois_admin["email"]

                                    if "name" in whois_admin: whois_name = whois_admin["name"]

                                    if "organization" in whois_admin: whois_organization = whois_admin["organization"]

                    if print_header:

                        header_string = "Domain Name - IP Address - Whois Name - Whois Organization - Whois Email - HTTP Similarity - HTTPS Similarity - Country - City"
                        logger.info("[+] {}".format(header_string))
                        if dns_file_new_created:
                            dns_file.write("{}\n".format(header_string))
                        print_header = False

                    string_to_write = "{} - {} - {} - {} - {} - {} - {} - {} - {}".format(result.get_domain_name(),
                                                                                result.get_ipaddress(),
                                                                                whois_name, whois_organization,
                                                                                whois_email,
                                                                                result.get_similarity()[
                                                                                    "http_similarity"],
                                                                                result.get_similarity()[
                                                                                    "https_similarity"],
                                                                                result.get_geolocation()["country_name"],
                                                                                result.get_geolocation()["city"])

                    logger.info(
                        "[+] {}".format(string_to_write))

                    if "{}\n".format(string_to_write) not in dns_file_content:
                        dns_file.write("{}\n".format(string_to_write))

        dns_file.close()

        if getsize(dns_file_name) == 0:
            remove(dns_file_name)

        logger.info("[*] {}".format(datetime.now()))


charset_json = None

if __name__ == '__main__':
    args = arg_parser()
    punyDomainCheck(args)
