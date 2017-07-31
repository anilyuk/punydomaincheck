# Puny Domain Check v1.0
# Author: Anil YUKSEL, Mustafa Mert KARATAS
# E-mail: anil [ . ] yksel [ @ ] gmail [ . ] com, mmkaratas92 [ @ ] gmail [ . ] com
# URL: https://github.com/anilyuk/punydomaincheck

class CharSetException(Exception):
    pass


class AlternativesExists(Exception):
    pass


class NoAlternativesFound(Exception):
    pass
