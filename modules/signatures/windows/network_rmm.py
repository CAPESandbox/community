# Copyright (C) 2026 bartblaze
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

import os
from urllib.parse import urlsplit

from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.common.constants import CUCKOO_ROOT

DOMAINS_FILE = os.path.join(CUCKOO_ROOT, "data", "rmm_domains.txt")


def normalize_domain(value):
    """Normalise a hostname for case-insensitive comparisons."""
    if not isinstance(value, str):
        return ""

    return value.strip().lower().rstrip(".")


def load_domains():
    domains = set()

    try:
        with open(DOMAINS_FILE, "r", encoding="utf-8") as handle:
            for line in handle:
                # Support empty lines, full-line comments, and inline comments.
                domain = line.split("#", 1)[0].strip()

                if domain:
                    domains.add(normalize_domain(domain))
    except OSError:
        return set()

    return domains


def match_domain(observed_domain, listed_domains):

    observed_domain = normalize_domain(observed_domain)

    if not observed_domain:
        return None

    for listed_domain in sorted(listed_domains, key=len, reverse=True):
        if observed_domain == listed_domain or observed_domain.endswith("." + listed_domain):
            return listed_domain

    return None


def hostname_from_url(value):
    """Extract and normalise the hostname from a URL."""
    if not isinstance(value, str):
        return ""

    value = value.strip()

    if not value:
        return ""

    if "://" not in value:
        value = "//" + value

    try:
        return normalize_domain(urlsplit(value).hostname)
    except ValueError:
        return ""


class NetworkDnsRmm(Signature):
    name = "network_dns_rmm"
    description = "Resolves a known remote access, RMM, or tunnelling service domain"
    severity = 2
    confidence = 60
    categories = ["network"]
    authors = ["bartblaze"]
    minimum = "2.0"
    ttps = ["T1219"]
    ttps += ["T1219.002"]
    references = [
        "https://lolrmm.io/api/rmm_tools.json",
        "bartblaze",
    ]

    def run(self):
        domains = load_domains()

        if not domains:
            return False

        matches = set()

        for record in self.results.get("network", {}).get("dns", []):
            if not isinstance(record, dict):
                continue

            dns_request = normalize_domain(record.get("request", ""))
            matched_domain = match_domain(dns_request, domains)

            if not matched_domain:
                continue

            match = (dns_request, matched_domain)

            if match in matches:
                continue

            matches.add(match)

            self.data.append(
                {
                    "dns_request": dns_request,
                    "matched_domain": matched_domain,
                }
            )

        return bool(matches)


class NetworkHttpRmm(Signature):
    name = "network_http_rmm"
    description = "Accesses a known remote access, RMM, or tunnelling service URL"
    severity = 2
    confidence = 60
    categories = ["network"]
    authors = ["bartblaze"]
    minimum = "2.0"
    evented = True
    ttps = ["T1219"]
    ttps += ["T1219.002"]
    references = [
        "https://lolrmm.io/api/rmm_tools.json",
        "bartblaze",
    ]

    filter_apinames = set(
        [
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "URLDownloadToCacheFileA",
            "URLDownloadToCacheFileW",
        ]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

        self.domains = load_domains()
        self.api_matches = set()

    def get_url_argument(self, call):
        """Handle common argument names used by monitored URL APIs."""
        for argument_name in ("URL", "lpszUrl", "Url"):
            url = self.get_argument(call, argument_name)

            if url:
                return url

        return ""

    def on_call(self, call, process):
        if not self.domains:
            return

        url = self.get_url_argument(call)
        hostname = hostname_from_url(url)
        matched_domain = match_domain(hostname, self.domains)

        if not matched_domain:
            return

        self.api_matches.add(
            (
                call.get("api", ""),
                url,
                hostname,
                matched_domain,
            )
        )

    def on_complete(self):
        matches = set()

        for api_name, url, hostname, matched_domain in sorted(self.api_matches):
            match = ("api", api_name, url, hostname, matched_domain)

            if match in matches:
                continue

            matches.add(match)

            self.data.append(
                {
                    "source": "api",
                    "api": api_name,
                    "url": url,
                    "hostname": hostname,
                    "matched_domain": matched_domain,
                }
            )

        # Processed HTTP traffic provides network-level HTTP confirmation.
        for request in self.results.get("network", {}).get("http", []):
            if not isinstance(request, dict):
                continue

            host = normalize_domain(request.get("host", ""))
            matched_domain = match_domain(host, self.domains)

            if not matched_domain:
                continue

            method = request.get("method", "")
            uri = request.get("uri", "")
            match = ("http", method, host, uri, matched_domain)

            if match in matches:
                continue

            matches.add(match)

            self.data.append(
                {
                    "source": "http",
                    "method": method,
                    "host": host,
                    "uri": uri,
                    "matched_domain": matched_domain,
                }
            )

        return bool(matches)
