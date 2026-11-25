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
            r".*\.3322\.net",
            r".*\.3322\.org",
            r".*\.accesscam\.org",
            r".*\.afraid\.org",
            r".*\.blogdns\.com",
            r".*\.camdvr\.org",
            r".*\.casacam\.net",
            r".*\.changeip\.com",
            r".*\.changeip\.net",
            r".*\.changeip\.org",
            r".*\.ddns\.me",
            r".*\.ddns\.net",
            r".*\.ddns\.us",
            r".*\.ddnsfree\.com",
            r".*\.ddnss\.de",
            r".*\.dnsalias\.com",
            r".*\.dnsdvr\.com",
            r".*\.dnsdynamic\.org",
            r".*\.dnsget\.org",
            r".*\.dnsip\.net",
            r".*\.dtdns\.net",
            r".*\.duckdns\.org",
            r".*\.dynalias\.com",
            r".*\.dyndns\.biz",
            r".*\.dyndns\.com",
            r".*\.dyndns\.info",
            r".*\.dyndns\.org",
            r".*\.dyndns\.tv",
            r".*\.dyndns\.ws",
            r".*\.dynu\.com",
            r".*\.dynu\.net",
            r".*\.dynv6\.net",
            r".*\.freedns\.afraid\.org",
            r".*\.freemyip\.com",
            r".*\.gotdns\.com",
            r".*\.homeftp\.net",
            r".*\.homeip\.net",
            r".*\.homelinux\.com",
            r".*\.homelinux\.net",
            r".*\.homelinux\.org",
            r".*\.homeunix\.com",
            r".*\.homeunix\.net",
            r".*\.homeunix\.org",
            r".*\.hopto\.org",
            r".*\.i234\.me",
            r".*\.ipv64\.de",
            r".*\.ipv64\.net",
            r".*\.linkpc\.net",
            r".*\.myddns\.me",
            r".*\.myds\.me",
            r".*\.myftp\.biz",
            r".*\.myftp\.name",
            r".*\.myftp\.org",
            r".*\.myfritz\.net",
            r".*\.mynetgear\.com",
            r".*\.myvnc\.com",
            r".*\.no-ip\.biz",
            r".*\.no-ip\.com",
            r".*\.no-ip\.info",
            r".*\.no-ip\.net",
            r".*\.no-ip\.org",
            r".*\.nsupdate\.info",
            r".*\.onmypc\.biz",
            r".*\.onmypc\.info",
            r".*\.onmypc\.net",
            r".*\.onmypc\.org",
            r".*\.redirectme\.net",
            r".*\.servebeer\.com",
            r".*\.serveblog\.net",
            r".*\.servecounterstrike\.com",
            r".*\.serveftp\.com",
            r".*\.servegame\.com",
            r".*\.servehalflife\.com",
            r".*\.servehttp\.com",
            r".*\.serveirc\.com",
            r".*\.servemp3\.com",
            r".*\.servepics\.com",
            r".*\.servequake\.com",
            r".*\.spdns\.de",
            r".*\.sytes\.net",
            r".*\.synology\.me",
            r".*\.xname\.org",
            r".*\.ydns\.eu",
            r".*\.zapto\.org",
        ]

        found_matches = False
        for indicator in domains_re:
            matches = self.check_domain(pattern=indicator, regex=True, all=True)
            if matches:
                found_matches = True
                for match in matches:
                    self.data.append({"domain": match})

        return found_matches
