# Puny Domain Check

Punycode is a special encoding used to convert Unicode characters to ASCII, which is a smaller, restricted character set. Punycode is used to encode internationalized domain names (IDN).

Confusable characters are from "http://www.unicode.org/Public/security/latest/confusables.txt". Update character set regularly to take new confusable characters!

To add new letters read [FILES.md](misc/FILES.md) file.

Punycode alternative domain names are widely used for phishing attacks. This tool helps to identify alternative domain names and look for several information of that domanin. It looks for DNS info, Whois info and open ports (TCP/443, TCP/80), Virustotal API.

When it finds a domain name with IP address, it checks similarities between original domain and warns you for phishing attack

#### Requirements: ####
* Virustotal API Key


#### Python requirements: ####
* coloredlogs
* pythonwhois
* bs4
* dnspython
* requests
* ratelimit
* tabulate

#### Usage: #### 
python punydomaincheck.py -d yourdomain -s com -os com -op 443 -c 2

    -u --update             Update character set
    --debug                 Enable debug logging
    -d --domain             Domain without prefix and suffix. (google)
    -s --suffix             Suffix to check alternative domain names. (.com, .net)
    -c --count              Character count to change with punycode alternative
    -os --original_suffix   Original domain to check for phisihing
    -op --original_port     Original port to check for phisihing
    -f --force              Force to create alternative domain names
    -t --thread             Thread count (Default: 10)


