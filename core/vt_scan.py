# Puny Domain Check v1.0
# Author: Anil YUKSEL, Mustafa Mert KARATAS
# E-mail: anil [ . ] yksel [ @ ] gmail [ . ] com, mmkaratas92 [ @ ] gmail [ . ] com
# URL: https://github.com/anilyuk/punydomaincheck

import requests
from ratelimit import rate_limited
from core.common import VT_APIKEY_LIST
from requests import packages

# Configurations

# Global Parameters
apikey_cursor = 0
vt_api_request_limit = 4

# Request URLs
vt_scan_url = "https://www.virustotal.com/vtapi/v2/url/scan"
vt_report_url = "http://www.virustotal.com/vtapi/v2/{type}/report"

# Constants values
http_method_get = "GET"
http_method_post = "POST"

vt_report_type_url = "url"
vt_report_type_domain = "domain"
vt_paramkey_resource = "resource"
vt_request_param_url = "url"
vt_request_param_domain = "domain"
vt_request_param_apikey = "apikey"
vt_request_param_scan = "scan"
vt_scan_scan_id = "scan_id"
vt_report_key_scans = "scans"
vt_report_key_positives = "positives"
vt_report_total = "total"
vt_report_key_subdomains = "subdomains"
vt_report_key_response_code = "response_code"


def scanURL(url):
    try:
        vt_url_result = virusTotalURLScan(url)
        vt_domain_search_result = virusTotalDomainSearch(url)

        return dict(vt_url_result, **vt_domain_search_result)
    except ValueError as err:
        return None
    except TypeError:
        return None


def virusTotalURLScan(url):
    params = {vt_request_param_url: url}
    scan_response = makeRequest(vt_scan_url, params, http_method_post)
    scan_response = scan_response.json()

    scan_report = virusTotalReport(vt_report_type_url, vt_paramkey_resource, scan_response[vt_scan_scan_id],
                                   http_method_post)

    return getScanReportResults(scan_report)


def virusTotalDomainSearch(domain):
    report = virusTotalReport(vt_report_type_domain, vt_request_param_domain, domain, http_method_get)

    return getDomainReportResults(report)


def virusTotalReport(report_type, report_type_param_key, report_id, http_method):
    params = {vt_request_param_scan: 1, report_type_param_key: report_id}

    report_url = vt_report_url.format(type=report_type)

    report = makeRequest(report_url, params, http_method)
    report = report.json()

    return report


def getScanReportResults(report):
    to_return = {}

    if report and report.has_key(vt_report_key_response_code) and int(report[vt_report_key_response_code]) == 1:

        if report.has_key(vt_report_key_positives):
            to_return[vt_report_key_positives] = report[vt_report_key_positives]

        if report.has_key(vt_report_total):
            to_return[vt_report_total] = report[vt_report_total]

        return to_return
    else:
        return None


def getDomainReportResults(report):
    to_return = {}

    if report and report.has_key(vt_report_key_response_code) and int(report[vt_report_key_response_code]) == 1:

        if report.has_key(vt_report_key_subdomains) and report[vt_report_key_subdomains]:
            to_return[vt_report_key_subdomains] = report[vt_report_key_subdomains]

        return to_return
    else:
        return None


@rate_limited(vt_api_request_limit * (len(VT_APIKEY_LIST) - 1),
              60)  # virustotal api has request limit: 4 request per minute
def makeRequest(url, params, http_method):
    params[vt_request_param_apikey] = changeApiKey()
    packages.urllib3.disable_warnings()
    if http_method == http_method_post:
        return requests.post(url, params=params, verify=False, timeout=25)
    else:
        return requests.get(url, params=params, verify=False, timeout=25)


def changeApiKey():
    global apikey_cursor

    apikey_cursor = apikey_cursor + 1

    if apikey_cursor >= len(VT_APIKEY_LIST):
        apikey_cursor = 0

    return VT_APIKEY_LIST[apikey_cursor]
