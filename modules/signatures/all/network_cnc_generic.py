# Copyright (C) 2018 Kevin Ross
# Copyright (C) 2024 Wassime BATTA
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
import os
from lib.cuckoo.common.constants import CUCKOO_ROOT
import ipaddress
import csv


def load_ip_ranges_from_csv(csv_file):
    ip_ranges = []
    with open(csv_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            ip_ranges.append(row['Prefix'])
    return ip_ranges


def check_ip_in_ranges(ip_address, ip_ranges):
    ip = ipaddress.ip_address(ip_address)
    for ip_range in ip_ranges:
        network = ipaddress.ip_network(ip_range)
        if ip in network:
            return True
    return False

msf_ips_file = "extra/msft-public-ips.csv"
msf_public_ips_list = os.path.join(CUCKOO_ROOT, msf_ips_file)
ip_ranges = load_ip_ranges_from_csv(msf_public_ips_list)


class NetworkCountryDistribution(Signature):
    name = "network_country_distribution"
    description = "Communicates with IPs located across a large number of unique countries"
    severity = 1
    confidence = 30
    categories = ["network", "c2"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    mbcs = ["B0030"]

    filter_analysistypes = set(["file"])

    def run(self):
        countries = []
        if "network" in self.results and "hosts" in self.results["network"]:
            for host in self.results["network"]["hosts"]:
                country = host["country_name"]
                if country and country not in countries:
                    countries.append(country)

        if len(countries) > 5:
            for uniq in countries:
                self.data.append({"country": uniq})

        if self.data:
            return True
        else:
            return False


class NetworkMultipleDirectIPConnections(Signature):
    name = "network_multiple_direct_ip_connections"
    description = "Multiple direct IP connections"
    severity = 2
    confidence = 30
    categories = ["network", "c2"]
    authors = ["Kevin Ross","Wassime BATTA"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        count = 0
        ips = []
        
        if "network" in self.results and "hosts" in self.results["network"]:
            for host in self.results["network"]["hosts"]:
                ip = host["ip"]
                hostname = host["hostname"]
                if ip not in ips and not hostname and not ip.startswith(("10.", "172.16.", "192.168.")):
                    # Verify whether they are not part of the MICROSOFT-CORP-MSN-AS-BLOCK.
                    if not check_ip_in_ranges(ip, ip_ranges):
                        ips.append(ip)
                        count += 1

        if count > 5:
            self.data.append({"direct_ip_connections": "Made direct connections to %s unique IP addresses" % (count)})

        if self.data:
            return True
        else:
            return False
