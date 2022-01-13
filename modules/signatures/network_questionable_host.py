# Copyright (C) 2021 Quadrant Information Security, written by Zane C. Bowers-Hadley
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

import dns.resolver

from lib.cuckoo.common.abstracts import Signature

class NetworkQuestionableHost(Signature):
    name = "network_questionable_host"
    description = "Communicates with a host in a RBL"
    severity = 4
    confidence = 80
    categories = ["network", "cnc"]
    authors = ["Zane C. Bowers-Hadley"]
    minimum = "1.3"

    filter_analysistypes = set(["file"])

    def run(self):
        resolver = dns.resolver.Resolver()
        resolver.timeout = 0.10
        RBLs=[
                'spam.spamrats.com',
                'web.dnsbl.sorbs.net',
                'auth.spamrats.com',
                'http.dnsbl.sorbs.net',
                'socks.dnsbl.sorbs.net',
                'misc.dnsbl.sorbs.net',
                'smtp.dnsbl.sorbs.net',
                'web.dnsbl.sorbs.net',
                'zombie.dnsbl.sorbs.net',
                'block.dnsbl.sorbs.net',
                'spam.dnsbl.sorbs.net',
                'noserver.dnsbl.sorbs.net',
                'escalations.dnsbl.sorbs.net',
                'noserver.dnsbl.sorbs.net',
                'zen.spamhaus.org',
             ]
        checked={}
        if "network" in self.results and "hosts" in self.results["network"]:
            for host in self.results["network"]["hosts"]:
                ip = host["ip"]
                checked[ip]=''
                if not ip.startswith(("10.", "172.16.", "192.168.")):
                    ipRev =  '.'.join( ip.split('.')[::-1])
                    for rbl in RBLs:
                        searchQuery = ipRev+'.'+rbl
                        try:
                            resolver.query(searchQuery,'A')
                            self.data.append({rbl : ip})
                        except:
                            print('')

        if "network" in self.results and "tcp" in self.results["network"]:
            for packet in self.results["network"]["tcp"]:
                ip = packet["dst"]
                if not ip.startswith(("10.", "172.16.", "192.168.")) and ip not in checked:
                    checked[ip]=''
                    ipRev =  '.'.join( ip.split('.')[::-1])
                    for rbl in RBLs:
                        searchQuery = ipRev+'.'+rbl
                        try:
                            resolver.query(searchQuery,'A')
                            self.data.append({rbl : ip})
                        except:
                            print('')

        if "network" in self.results and "udp" in self.results["network"]:
            for packet in self.results["network"]["udp"]:
                ip = packet["dst"]
                if not ip.startswith(("10.", "172.16.", "192.168.")) and ip not in checked:
                    checked[ip]=''
                    ipRev =  '.'.join( ip.split('.')[::-1])
                    for rbl in RBLs:
                        searchQuery = ipRev+'.'+rbl
                        try:
                            resolver.query(searchQuery,'A')
                            self.data.append({rbl : ip})
                        except:
                            print('')

        if "network" in self.results and "icmp" in self.results["network"]:
            for packet in self.results["network"]["icmp"]:
                ip = packet["dst"]
                if not ip.startswith(("10.", "172.16.", "192.168.")) and ip not in checked:
                    checked[ip]=''
                    ipRev =  '.'.join( ip.split('.')[::-1])
                    for rbl in RBLs:
                        searchQuery = ipRev+'.'+rbl
                        try:
                            resolver.query(searchQuery,'A')
                            self.data.append({rbl : ip})
                        except:
                            print('')
                ip = packet["src"]
                if not ip.startswith(("10.", "172.16.", "192.168.")) and ip not in checked:
                    checked[ip]=''
                    ipRev =  '.'.join( ip.split('.')[::-1])
                    for rbl in RBLs:
                        searchQuery = ipRev+'.'+rbl
                        try:
                            resolver.query(searchQuery,'A')
                            self.data.append({rbl : ip})
                        except:
                            print('')

        if self.data:
            return True
        else:
            return False
