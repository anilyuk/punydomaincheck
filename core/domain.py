# Puny Domain Check v1.0
# Author: Anil YUKSEL, Mustafa Mert KARATAS
# E-mail: anil [ . ] yksel [ @ ] gmail [ . ] com, mmkaratas92 [ @ ] gmail [ . ] com
# URL: https://github.com/anilyuk/punydomaincheck

from core.common import alternative_filename, GEOLOCATION_WEBSITE, VT_APIKEY_LIST
from threading import Thread
import dns.resolver
from phishingdomain import PhishingDomain
from pythonwhois import get_whois
from phishingtest import CheckPhishing
import requests
if VT_APIKEY_LIST:
    from core.vt_scan import scanURL

class dns_client(Thread):
    def __init__(self, args, logger, domain_list, output_queue, thread_name):

        Thread.__init__(self)

        self.domain_list = domain_list
        self.output_queue = output_queue
        self.output_list = []
        self.args = args
        self.logger = logger
        self.thread_name = thread_name
        self.resolver = None
        self.percentage = 0

    def run(self):

        count = 0
        last_percentage = 1
        total = len(self.domain_list)

        for domain in self.domain_list:

            if len(domain) > 1:
                query = domain + "." + self.args.suffix
                dns_result = self.query_dns(query)
                # whois_result = self.query_whois(query)

                # if not dns_result and whois_result:
                #    result = PhishingDomain(domain_name=domain, ipaddress=str("No DNS Record"),
                # whois_result=whois_result)
                #    self.output_list.append(result)

                # else:

                if dns_result:

                    whois_result = self.query_whois(query)

                    for answer in dns_result:
                        result = PhishingDomain(domain_name=domain, ipaddress=str(answer),
                                                whois_result=whois_result)

                        geolocation_result = self.query_geolocation(ip_address=answer)
                        result.set_geolocation(geolocation=geolocation_result)

                        if VT_APIKEY_LIST:
                            result.set_vt_result(scanURL(url=query))

                        if self.args.domain and self.args.original_suffix:

                            original_domain = "{}.{}".format(self.args.domain, self.args.original_suffix)
                            similarity = CheckPhishing(or_domain=original_domain, or_site_port=self.args.original_port,
                                                       test_domain=str(query), logger=self.logger)
                            result.set_similarity(similarity=similarity)

                        self.output_list.append(result)

            count += 1

            self.percentage = int((100 * count) / total)
            if last_percentage != self.percentage:
                # self.logger.info("Thread{} - {}% Completed".format(self.thread_name, percentage))
                last_percentage = self.percentage

        self.output_queue.put(self.output_list)

    def get_percentage(self):

        return self.percentage

    def query_dns(self, query):

        try:
            self.resolver = dns.resolver.Resolver()
            self.resolver.timeout = 1
            self.resolver.lifetime = 1
            # ip_address = gethostbyname(query)
            answers = self.resolver.query(query)

        # except gaierror, g:
        except dns.resolver.NXDOMAIN, n:
            self.logger.debug("[-] {}".format(n))
            return None

        except dns.resolver.Timeout, t:
            self.logger.debug("[-] {}".format(t))
            return None
        except dns.resolver.NoNameservers, n:
            self.logger.debug("[-] {}".format(n))
            return None

        except Exception, e:
            self.logger.debug("[-] {}".format(e))
            return None

        else:

            if answers:
                return answers
            else:
                return None

    def query_whois(self, query):

        try:

            whois_result = get_whois(domain=query)

            if "raw" in whois_result:

                if "No match" in str(whois_result["raw"][0]):
                    return None

                else:
                    return whois_result

            else:

                return None

        except UnicodeDecodeError, e:

            self.logger.debug(e)
            return None

        except UnicodeEncodeError, e:

            self.logger.debug(e)
            return None

        except:

            self.logger.debug(e)
            return None

    def query_geolocation(self, ip_address):

        response = requests.get("{}/{}".format(GEOLOCATION_WEBSITE, ip_address))
        json_response = response.json()
        return json_response


def load_domainnames(args, output_dir):

    alternatives_file = open(alternative_filename(args, output_dir))
    alternatives = alternatives_file.read().split("\n")

    thread_count = int(args.thread)
    if len(alternatives) < thread_count: thread_count = len(alternatives)
    alternatives_list = create_chunks(alternatives, int(thread_count))

    return alternatives_list


def create_chunks(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out
