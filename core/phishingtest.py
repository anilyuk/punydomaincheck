# Puny Domain Check v1.0
# Author: Anil YUKSEL, Mustafa Mert KARATAS
# E-mail: anil [ . ] yksel [ @ ] gmail [ . ] com, mmkaratas92 [ @ ] gmail [ . ] com
# URL: https://github.com/anilyuk/punydomaincheck

import socket
from requests import get, packages, exceptions
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
import re

SOCKET_TIMEOUT_SECONDS = 1


class PhishingTest:
    similarity_checks = None  # SimilarityCheck object
    ip_match = None  # Boolean comparison
    port_match = None  # Boolean comparison

    def __init__(self):
        self.similarity_checks = None
        self.ip_match = None
        self.port_match = None

    def toDictionary(self):
        temp = []
        if self.similarity_checks:
            for item in self.similarity_checks:
                temp.append(item.toDictionary())
        toReturn = {"ip_match": self.ip_match, "port_match": self.port_match, "similarity_checks": temp}
        return toReturn


class SimilarityCheck:
    test_url = None  # String url
    visible_text = None  # Double ratio
    external_link = None  # Double ratio
    external_link_site = None

    def __init__(self):
        pass

    def toDictionary(self):
        toReturn = {"test_url": self.test_url, "visible_text": self.visible_text, "external_link": self.external_link,
                    "external_link_site": self.external_link_site
                    }
        return toReturn


class HttpResponse:
    url = None
    status_code = None
    source_code = None

    def __init__(self, url=None, status_code=None, source_code=None):
        self.url = url
        self.status_code = status_code
        self.source_code = source_code

    def toDictionary(self):
        toReturn = {"url": self.url, "status_code": self.status_code, "source_code": self.source_code}
        return toReturn


def checkOpenPorts(ip_address, ports=-1):
    open_ports = []

    if ports == -1 or len(ports) < 1:
        ports = [80, 443]

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT_SECONDS)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports


def getIPAddress(domain_name):
    try:
        return socket.gethostbyname(domain_name)
    except:
        return None


def addProtocol(domain_name, http_port=80):
    if http_port == 80:
        return "http://" + domain_name
    else:
        return "https://" + domain_name


def makeRequest(url, logger, redirect=True, proxies={}):
    packages.urllib3.disable_warnings()
    try:

        response = get(url, allow_redirects=redirect, verify=False, proxies=proxies, timeout=25)
        newurl = "{}/{}".format(url, meta_redirect(response.text))

        while newurl:
            response = get(newurl, allow_redirects=redirect, verify=False, proxies=proxies, timeout=25)
            newurl = meta_redirect(response.text)

    except exceptions.ConnectionError, e:

        logger.debug("[-] {} - {}".format(url, str(e)))
        return

    except exceptions.ReadTimeout, e:

        logger.debug("[-] {} - {}".format(url, str(e)))
        return

    else:

        return parseResponse(response)


def meta_redirect(content):
    soup = BeautifulSoup(content, "html.parser")
    result = soup.find("meta", attrs={"http-equiv": re.compile("^refresh", re.I)})
    if result:
        wait, text = result["content"].split(";")
        if text.strip().lower().startswith("url="):
            url = text[4:]
            return url
    return ""


def parseResponse(requests_response):
    toReturn = HttpResponse()

    toReturn.url = requests_response.url
    toReturn.status_code = requests_response.status_code
    toReturn.source_code = requests_response.text.encode("utf-8")

    return toReturn


def checkVisibleTextSimilarity(original_source, test_source):
    original_soup = BeautifulSoup(original_source, 'html.parser')
    test_soup = BeautifulSoup(test_source, 'html.parser')

    original_text = grabText(original_soup)
    original_text = makeSingleString(original_text)

    test_text = grabText(test_soup)
    test_text = makeSingleString(test_text)

    return similarity(original_text, test_text)


def checkExternalLinkSimilarities(original_source, test_source, or_url):
    original_soup = BeautifulSoup(original_source, 'html.parser')
    test_soup = BeautifulSoup(test_source, 'html.parser')

    original_links = grabLinks(original_soup)
    test_links = grabLinks(test_soup)

    if len(original_links) == 0 or len(test_links) == 0:

        return (0, 0)

    else:

        return (calculateLinkSimilarity(original_links, test_links), checkOriginalDomainExist(or_url, test_links))


def grabText(soup):
    toReturn = soup.findAll(text=True)
    return filter(visibleTextFilter, toReturn)


def visibleTextFilter(element):
    tags = ['style', 'script', '[document]', 'head', 'link']
    if element.parent.name in tags:
        return False
    elif re.match('<!--.*-->', str(element.encode("utf-8"))):
        return False
    elif element.name in tags:
        return False
    else:
        return True


def makeSingleString(str_list):
    toReturn = ""
    for item in str_list:
        toReturn = toReturn + item

    toReturn = toReturn.encode("utf-8")
    toReturn = "".join(toReturn.split())
    return toReturn


def similarity(a, b):
    return str(round(SequenceMatcher(None, a, b).ratio() * 100, 2))


def grabLinks(soup):
    toReturn = []
    toReturn = toReturn + find_list_resources('img', "src", soup)
    toReturn = toReturn + find_list_resources('script', "src", soup)
    toReturn = toReturn + find_list_resources("link", "href", soup)
    toReturn = toReturn + find_list_resources("video", "src", soup)
    toReturn = toReturn + find_list_resources("audio", "src", soup)
    toReturn = toReturn + find_list_resources("iframe", "src", soup)
    toReturn = toReturn + find_list_resources("embed", "src", soup)
    toReturn = toReturn + find_list_resources("object", "data", soup)
    toReturn = toReturn + find_list_resources("source", "src", soup)
    toReturn = toReturn + find_list_resources("form", "action", soup)
    return toReturn


def find_list_resources(tag, attribute, soup):
    toReturn = []
    for x in soup.findAll(tag):
        try:
            toReturn.append(x[attribute])
        except KeyError:
            pass
    return toReturn


def calculateLinkSimilarity(original_links, test_links):
    total_original_links = len(original_links)

    for test_link in test_links:

        for i in range(0, len(original_links)):
            if test_link == original_links[i]:
                original_links.pop(i)
                break

    remaning_original_links = len(original_links)

    return (total_original_links - remaning_original_links) * 100 / total_original_links


def checkOriginalDomainExist(or_site, test_links):
    count = 0

    for test_link in test_links:

        if or_site in test_link:
            count += 1

    return (100 * count) / len(test_links)


def CheckPhishing(or_domain, or_site_port, test_domain, logger):
    test_result = PhishingTest()

    or_url = addProtocol(or_domain, or_site_port)

    or_ip = getIPAddress(or_domain)

    or_site = makeRequest(or_url, logger)

    test_ip = getIPAddress(test_domain)

    if test_ip and or_ip:
        test_ports = checkOpenPorts(test_ip)
        test_urls = []
        for port in test_ports:
            test_urls.append(addProtocol(test_domain, port))

        similarity_checks = []
        for test_url in test_urls:
            test_site = makeRequest(test_url, logger)
            if test_site:
                temp = SimilarityCheck()
                temp.test_url = test_url
                or_site.toDictionary()
                # print test_site.source_code
                temp.visible_text = checkVisibleTextSimilarity(or_site.source_code, test_site.source_code)
                temp.external_link, temp.external_link_site = checkExternalLinkSimilarities(or_site.source_code,
                                                                                            test_site.source_code,
                                                                                            or_domain)
                similarity_checks.append(temp)

        test_result.similarity_checks = similarity_checks
        test_result.ip_match = (or_ip == test_ip)
        test_result.port_match = (len(test_ports) == 1 and test_ports[0] == or_site_port)

    http_similarity = None
    https_similarity = None

    test_result = test_result.toDictionary()

    if not test_result["ip_match"]:

        similarity_checks = test_result["similarity_checks"]

        for item in similarity_checks:

            if float(item["visible_text"]) > 40 or float(item["external_link"]) > 40 or float(
                    item["external_link_site"]):

                if "https://" in item["test_url"]:

                    https_similarity = True

                else:

                    http_similarity = True

            else:

                if "https://" in item["test_url"]:

                    https_similarity = False

                else:

                    http_similarity = False

        return {"http_similarity": http_similarity, "https_similarity": https_similarity}

    else:

        return {"http_similarity": False, "https_similarity": False}
