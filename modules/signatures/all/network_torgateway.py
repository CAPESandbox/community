# Copyright (C) 2014 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class TorGateway(Signature):
    name = "network_torgateway"
    description = "Connects to Tor Hidden Services through a Tor gateway"
    severity = 3
    categories = ["network"]
    authors = ["nex", "Optiv"]
    minimum = "1.2"
    ttps = ["T1188"]  # MITRE v6
    ttps += ["T1090"]  # MITRE v6,7,8
    ttps += ["T1090.003"]  # MITRE v7,8
    ttps += ["U0903"]  # Unprotect

    def run(self):
        domain_indicators = [
            r".*\.tor2web\.([a-z]{2,3})$",
            r".*\.bortor\.com$",
            r".*\.torpacho\.com$",
            r".*\.torsanctions\.com$",
            r".*\.torwild\.com$",
            r".*\.pay2tor\.com$",
            r".*\.tor2pay\.com$",
            r".*\.tor4pay\.com$",
            r".*\.pay4tor\.com$",
            r".*\.torexplorer\.com$",
            r".*\.onion\.to$",
            r".*\.onion\.cab$",
            r".*\.onion\.city$",
            r".*\.tor\-gateways\.de$",
            r".*\.tor2web\.blutmagie\.de$",
            r".*\.torpaycash\.com$",
            r".*\.torconnectpay\.com$",
            r".*\.torwalletpay\.com$",
            r".*\.walterwhitepay\.com$",
            r".*\.rossulbrichtpay\.com$",
            r".*\.42k2bu15\.com$",
            r".*\.79fhdm16\.com$",
            r".*\.myportopay\.com$",
            r".*\.vivavtpaymaster\.com$",
            r".*\.fraspartypay\.com$",
        ]
        ip_indicators = ["195.85.254.203"]
        found_torgateway = False
        for indicator in domain_indicators:
            domains = self.check_domain(pattern=indicator, regex=True, all=True)
            if domains:
                for domain in domains:
                    self.data.append({"domain": domain})
                    found_torgateway = True
        for indicator in ip_indicators:
            ip = self.check_ip(pattern=indicator)
            if ip:
                self.data.append({"ip": ip})
                found_torgateway = True

        return found_torgateway
