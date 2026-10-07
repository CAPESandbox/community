# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class NetworkDynDNS(Signature):
    name = "network_dyndns"
    description = "Connects to a Dynamic DNS Domain"
    severity = 2
    categories = ["network"]
    authors = ["RedSocks"]
    minimum = "1.2"
    ttps = ["T1568"]
    mbcs = ["B0030"]

    def run(self):
        domains_re = [
            r".*\\.no-ip\\.",
            r".*\\.strangled\\.net",
            r".*\\.noip\\.",
            r".*\\.x64\\.me",
            r".*\\.ddns\\.",
            r".*\\.myvnc\\.com",
            r".*\\.user32\\.com",
            r".*\\.dyndns\\.",
            r".*\\.codns\\.com",
            r".*\\.servebeer\\.",
            r".*\\.serveminecraft\\.",
            r".*\\.servebbs\\.",
            r".*\\.serveblog\\.",
            r".*\\.servecounterstrike\\.",
            r".*\\.ntdll\\.net",
            r".*\\.servehttp\\.",
            r".*\\.bounceme\\.net",
            r".*\\.servequake\\.com",
            r".*\\.3utilities\\.",
            r".*\\.redirectme\\.net",
            r".*\\.servehalflife\\.com",
            r".*\\.gicp\\.net",
            r".*\\.zapto\\.org",
            r".*\\.hopto\\.org",
            r".*\\.tftpd\\.net",
            r".*\\.myq-see\\.com",
            r".*\\.3322\\.org",
            r".*\\.8866\\.org",
            r".*\\.sytes\\.net",
            r".*\\.serveftp\\.",
            r".*\\.servemp3\\.",
            r".*\\.mooo\\.com",
            r".*\\.dnsget\\.org",
            r".*\\.f3322\\.org",
            r".*\\.publicvm\\.com",
            r".*\\.dlinkddns\\.com",
            r".*\\.authorizeddns\\.",
            r".*\\.chickenkiller\\.",
            r".*\\.8800\\.org",
            r".*\\.adultdns\\.",
            r".*\\.myfreeip\\.",
            r".*\\.linkpc\\.net",
            r".*\\.myftp\\.",
            r".*\\.servegame\\.",
            r".*\\.ignorelist\\.",
            r".*\\.duckdns\\.org",
            r".*\\.ddnsking\\.",
            r".*\\.hopper\\.pw",
            r".*\\.couchpotatofries\\.",
            r".*\\.dyndns.*ip\\.com",
            r".*\\.dynamic-dns\\.net",
            r".*\\.now-ip.org\\.net",
            r".*\\.now-ip.net\\.net",
            r".*\\.now-ip.net\\.xyz",
            r".*\\.zapto\\.xyz",
            r".*\\.mypi\\.co",
            r".*\\.001www.com\\.com",
            r".*\\.16-b\\.it",
            r".*\\.32-b\\.it",
            r".*\\.64-b\\.it",
            r".*\\.crafting\\.xyz",
            r".*\\.forumz\\.info",
            r".*\\.hicam\\.net",
            r".*\\.myiphost\\.com",
            r".*\\.mypi\\.co",
            r".*\\.n4t\\.co",
            r".*\\.tcp4\\.me",
            r".*\\.x443\\.pw",
        ]

        found_matches = False
        for indicator in domains_re:
            matches = self.check_domain(pattern=indicator, regex=True, all=True)
            if matches:
                found_matches = True
                for match in matches:
                    self.data.append({"domain": match})

        return found_matches
