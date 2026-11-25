# Copyright (C) 2026 bartblaze
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

import re

from lib.cuckoo.common.abstracts import Signature


class NetworkIPEmbeddedDNS(Signature):
    name = "network_ip_embedded_dns"
    description = "Connects to an IP-embedded DNS service."
    severity = 2
    categories = ["network", "evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    reference = "https://github.com/cunnie/sslip.io"
    ttps = ["T1568"]

    domains = [
        r".*\.a-i\.sh",
        r".*\.a-i\.st",
        r".*\.backname\.io",
        r".*\.nip\.io",
        r".*\.nip\.nu",
        r".*\.nsrecord\.net",
        r".*\.qip\.sh",
        r".*\.sslip\.io",
        r".*\.traefik\.me",
    ]

    def on_complete(self):
        for domain in self.results["network"]["domains"]:
            for regex in self.domains:
                if re.match(regex, domain["domain"]):
                    self.data.append({"domain": domain["domain"]})
                    return True

        return False

