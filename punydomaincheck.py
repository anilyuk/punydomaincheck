# Puny Domain Check v1.0
# Author: Anil YUKSEL, Mustafa Mert KARATAS
# E-mail: anil [ . ] yksel [ @ ] gmail [ . ] com, mmkaratas92 [ @ ] gmail [ . ] com
# URL: https://github.com/anilyuk/punydomaincheck

from argparse import ArgumentParser, RawTextHelpFormatter
from sys import exit

from core.creator import *
from core.exceptions import CharSetException, AlternativesExists
from core.logger import start_logger
from core.confusable import update_charset
from core.domain import load_domainnames, dns_client
from core.common import print_percentage, OUTPUT_DIR, BANNER, BLU, RST, RED, GRE, VT_APIKEY_LIST
from time import sleep
from Queue import Queue
from os.path import getsize
from tabulate import tabulate
from os import remove, mkdir, stat
from core.phishingdomain import PhishingDomain

if VT_APIKEY_LIST:
    from core.vt_scan import vt_report_key_positives, vt_report_total, vt_report_key_subdomains, scanURL

def arg_parser():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument("-u", "--update", action="store_true", default=False, help="Update character set")
    parser.add_argument("--debug", action="store_true", default=False, help="Enable debug logging")
    parser.add_argument("-d", "--domain", default=None, help="Domain without prefix and suffix. (google)")
    parser.add_argument("-s", "--suffix", default=None, help="Suffix to check alternative domain names. (.com, .net)")
    parser.add_argument("-c", "--count", default=1, help="Character count to change with punycode alternative (Default: 1)")
    parser.add_argument("-os", "--original_suffix", default=None,
                        help="Original domain to check for phisihing\n"
                        "Optional, use it with original port to run phishing test")
    parser.add_argument("-op", "--original_port", default=None, help="Original port to check for phisihing\n"
                                                                   "Optional, use it with original suffix to run phishing test")
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Force to calculate alternative domain names")
    parser.add_argument("-t", "--thread", default=15, help="Thread count")

    return parser.parse_args()


def punyDomainCheck(args, logger):
    letters_json = load_letters()

    if args.original_port and not args.original_suffix:

        logger.info("[-] Original suffix required!")
        exit()

    elif not args.original_port and args.original_suffix:

        logger.info("[-] Original port required!")
        exit()

    try:

        charset_json = load_charset()

    except CharSetException:

        if (not args.update):
            update_charset(logger, letters_json)
            charset_json = load_charset()

    if args.update:
        update_charset(logger, letters_json)

    elif int(args.count) <= len(args.domain):

        if not args.domain:
            logger.info("[-] Domain name required!")
            exit()

        if not args.suffix:
            logger.info("[-] Domian Suffix required!")
            exit()

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
        except KeyboardInterrupt:
            exit()

        domain_name_list = load_domainnames(args=args, output_dir=output_dir)
        dns_thread_list = []
        threads_queue = []
        thread_count = 0
        logger.info("[*] Every thread will resolve {}{}{} names".format(BLU, str(len(domain_name_list[0])), RST))
        # logger.info("[*] {}".format(datetime.now()))

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

        logger.info("[*] DNS Client thread started. Thread count: {}{}{}".format(BLU, len(dns_thread_list), RST))

        dns_client_completed = False
        query_result = []

        last_percentage = 1
        header_print = False

        while not dns_client_completed:

            try:
                sleep(0.001)
            except KeyboardInterrupt:
                print RST
                exit()

            total_percentage = 0

            for dns_thread in dns_thread_list:
                total_percentage += dns_thread.get_percentage()

            total_percentage = total_percentage / int(thread_count)

            last_percentage, header_print = print_percentage(args, logger, total_percentage,
                                                             last_percentage=last_percentage,
                                                             header_print=header_print)

            for queue in threads_queue:
                try:

                    if not queue.empty():
                        query_result.append(queue.get())
                except KeyboardInterrupt:
                    print RST
                    exit()

            if len(query_result) == int(thread_count):
                dns_client_completed = True

        if VT_APIKEY_LIST:

            logger.info("[*] Checking for VirusTotal")

            for results in query_result:

                for result in results:
                    result.set_vt_result(scanURL(url=(result.get_domain_name()+"."+str(args.suffix))))
                    # VirusTotal Free has 4 request per minute requests limit and sleep time is set based on this.
                    # If you have VirusTotal Premium membership change sleep value based on your limits.
                    sleep((60/(len(VT_APIKEY_LIST) * 4)) + 2)

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

        headers_list = ["","Domain Name", "IP Address", "Whois Name", "Whois Organization", "Whois Email",
                        "Whois Updated Date", "HTTP Similarity", "HTTPS Similarity",
                        "Country", "City", "Virustotal Result", "Subdomains",""]

        dns_file = open(dns_file_name, 'a')
        string_array = []

        for results in query_result:

            for result in results:

                if len(result.get_domain_name()) > 1:

                    whois_email = ""
                    whois_name = ""
                    whois_organization = ""
                    whois_creation_date = ""
                    whois_updated_date = ""
                    whois_result = result.get_whois_result()

                    if whois_result:

                        if "contacts" in whois_result:

                            whois_contacts = whois_result["contacts"]

                            if "admin" in whois_contacts:

                                whois_admin = whois_contacts["admin"]

                                if whois_admin:

                                    if "email" in whois_admin: whois_email = whois_admin["email"]
                                    else: whois_email="NA"

                                    if "name" in whois_admin: whois_name = whois_admin["name"]
                                    else: whois_name = "NA"

                                    if "organization" in whois_admin: whois_organization = whois_admin["organization"]
                                    else: whois_organization = "NA"
                            else:
                                whois_email = "NA"
                                whois_name = "NA"
                                whois_organization = "NA"

                        if "updated_date" in whois_result: whois_updated_date = whois_result["updated_date"][0]

                    if print_header:

                        header_string = ";".join(headers_list[1:-1])

                        if dns_file_new_created:
                            dns_file.write("{}\n".format(header_string))
                        print_header = False

                    http_similarity = ""
                    https_similarity = ""
                    if "http_similarity" in result.get_similarity():
                        http_similarity = result.get_similarity()["http_similarity"]
                    if "https_similarity" in result.get_similarity():
                        https_similarity = result.get_similarity()["https_similarity"]

                    virustotal_result = ""
                    subdomains = ""

                    if result.get_vt_result():
                        virustotal_result = "{}/{}".format(
                            result.get_vt_result()[vt_report_key_positives], result.get_vt_result()[vt_report_total])
                        if vt_report_key_subdomains in result.get_vt_result():
                            subdomains = ",".join(result.get_vt_result()[vt_report_key_subdomains])


                    country_name = result.get_geolocation().country.name

                    city_name = result.get_geolocation().city.name
                    
                    string_to_write = "{};{};{};{};{};{};{};{};{};{};{};{};{}".format(
                        result.get_domain_name(),
                        result.get_ipaddress(),
                        whois_name,
                        whois_organization,
                        whois_email,
                        whois_creation_date,
                        whois_updated_date,
                        http_similarity,
                        https_similarity,
                        country_name,
                        city_name,
                        virustotal_result,
                        subdomains)
                    color = ""
                    if "{}\n".format(string_to_write) not in dns_file_content:
                        dns_file.write("{}\n".format(string_to_write))
                        color = RED

                    string_array.append(
                        [color, result.get_domain_name(),
                         result.get_ipaddress(),
                         whois_name,
                         whois_organization,
                         whois_email,
                         whois_updated_date,
                         http_similarity,
                         https_similarity,
                         country_name,
                         city_name,
                         virustotal_result,
                         subdomains, RST])


        logger.info(
            "[+] Punycheck result for {}{}.{}{}:\n {}".format(GRE, args.domain, args.suffix, RST,
                                                              tabulate(string_array, headers=headers_list)))

        dns_file.close()

        if getsize(dns_file_name) == 0:
            remove(dns_file_name)

            # logger.info("[*] {}".format(datetime.now()))


charset_json = None

if __name__ == '__main__':
    print '%s%s%s' % (BLU, BANNER, RST)

    args = arg_parser()
    logger = start_logger(args)
    punyDomainCheck(args, logger)
