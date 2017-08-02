# Puny Domain Check v1.0
# Author: Anil YUKSEL, Mustafa Mert KARATAS
# E-mail: anil [ . ] yksel [ @ ] gmail [ . ] com, mmkaratas92 [ @ ] gmail [ . ] com
# URL: https://github.com/anilyuk/punydomaincheck

class PhishingDomain:

    def __init__(self, domain_name, ipaddress, whois_result=""):

        self.domain_name = domain_name
        self.ipaddress = ipaddress
        self.whois_result = whois_result
        self.similarity = ""
        self.geolocation = None
        self.vt_result = None

    def get_domain_name(self):

        return self.domain_name

    def get_ipaddress(self):

        return self.ipaddress

    def get_whois_result(self):

        return self.whois_result

    def set_whois_result(self, whois_result):

        self.whois_result = whois_result

    def set_similarity(self, similarity):

        self.similarity = similarity

    def get_similarity(self):

        return self.similarity

    def set_geolocation(self, geolocation):

        self.geolocation = geolocation

    def get_geolocation(self):

        return self.geolocation

    def get_vt_result(self):

        return self.vt_result

    def set_vt_result(self, vt_result):

        self.vt_result = vt_result