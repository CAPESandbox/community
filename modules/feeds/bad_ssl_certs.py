# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Feed


class AbuseCH_SSL(Feed):
    # Results dict key value / exception handling / logging name
    name = "Bad_SSL_Certs"
    # Change the below line to enable this feed
    enabled = True

    def __init__(self):
        super().__init__()
        # Location of the feed to be fetched
        self.downloadurl = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
        # Used in creating the file path on disk
        self.feedname = "abuse_ch_ssl"
        # How much time must pass (in hours) before we update
        self.frequency = 6

    def modify(self):
        newdata = ""
        seen = set()
        for line in (self.downloaddata or "").splitlines():
            line = line.strip()
            # skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # split into fields: Listingdate,SHA1,Listingreason
            parts = line.split(",")
            # skip header or malformed lines
            if parts[0].lower().startswith("listingdate"):
                continue
            if len(parts) < 2:
                continue

            sha1 = parts[1].strip()
            reason = parts[2].strip() if len(parts) > 2 else ""

            if not sha1:
                continue

            if sha1 in seen:
                continue

            seen.add(sha1)
            newdata += f"{sha1},{reason}\n"

        # Save modified content to self.data (required by Feed)
        self.data = newdata
