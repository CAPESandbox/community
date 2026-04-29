# Copyright (C) 2026
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

"""BYOD (Bring-Your-Own-Driver) signatures — consume results['loldrivers'] from the
loldrivers processing module."""

from lib.cuckoo.common.abstracts import Signature

SEVERITY_BY_TIER = {
    "definitive_sha256": 5,
    "high_signer_name": 4,
    "medium_name": 3,
}


class ByodLolDriversMatch(Signature):
    name = "byod_loldrivers_match"
    description = "Sample loaded a known vulnerable or malicious driver from the LOLDrivers catalog"
    severity = 4
    weight = 4
    confidence = 100
    categories = ["evasion", "privilege-escalation"]
    authors = ["dnsgeeo"]
    minimum = "1.3"
    ttps = ["T1068", "T1014", "T1562.001"]
    references = ["https://www.loldrivers.io/"]
    mbcs = ["E1068"]

    def run(self):
        bd = self.results.get("loldrivers") or {}
        matches = bd.get("matches") or []
        if not matches:
            return False
        max_sev = 3
        for m in matches:
            tier = m.get("tier")
            sample_under_test = m.get("sample_under_test")
            self.data.append(
                {
                    "tier": tier,
                    "loldrivers_id": m.get("loldrivers_id"),
                    "category": m.get("category"),
                    "filename": m.get("matched_filename"),
                    "path": m.get("path"),
                    "sha256": m.get("sha256"),
                    "signer": m.get("signer"),
                    "reason": m.get("reason"),
                    "sample_under_test": bool(sample_under_test),
                }
            )
            sev = SEVERITY_BY_TIER.get(tier, 3)
            # Sample uploaded for analysis matches by hash → still informational, but cap severity.
            if sample_under_test:
                sev = min(sev, 3)
            if sev > max_sev:
                max_sev = sev
        self.severity = max_sev
        return True


class ByodNovelDriver(Signature):
    name = "byod_novel_driver"
    description = "Sample loaded an unsigned/non-system driver — possible novel BYOD"
    severity = 3
    weight = 3
    confidence = 70
    categories = ["evasion"]
    authors = ["dnsgeeo"]
    minimum = "1.3"
    ttps = ["T1068", "T1014"]

    def run(self):
        bd = self.results.get("loldrivers") or {}
        novel = bd.get("novel_candidates") or []
        if not novel:
            return False
        for n in novel:
            self.data.append(
                {
                    "path": n.get("path"),
                    "sha256": n.get("sha256"),
                    "signed": n.get("signed"),
                    "signature_status": n.get("signature_status"),
                    "signer": n.get("signer"),
                    "creator_name": n.get("creator_name"),
                    "creator_pid": n.get("creator_pid"),
                    "signals": n.get("signals"),
                    "time": n.get("time"),
                }
            )
        return True


class ByodPostLoadExploitation(Signature):
    name = "byod_post_load_exploitation"
    description = "Driver load was followed by termination of EDR/AV/sandbox tooling"
    severity = 5
    weight = 5
    confidence = 90
    categories = ["evasion", "defense-evasion"]
    authors = ["dnsgeeo"]
    minimum = "1.3"
    ttps = ["T1562", "T1562.001", "T1562.004", "T1068"]

    def run(self):
        bd = self.results.get("loldrivers") or {}
        expl = bd.get("exploitation") or []
        if not expl:
            return False
        for batch in expl:
            for f in batch.get("findings") or []:
                self.data.append(
                    {
                        "driver_path": batch.get("driver_path"),
                        "driver_sha256": batch.get("driver_sha256"),
                        "driver_time": batch.get("driver_time"),
                        "kind": f.get("kind"),
                        "finding_severity": f.get("severity"),
                        "tool": f.get("tool"),
                        "vendor": f.get("vendor"),
                        "category": f.get("category"),
                        "detail": f.get("detail"),
                        "image": f.get("image"),
                        "time": f.get("time"),
                    }
                )
        return True


class ByodServiceInstall(Signature):
    name = "byod_driver_service_install"
    description = "Sample-attributed kernel-mode driver service install — possible BYOD setup"
    severity = 3
    weight = 2
    confidence = 80
    categories = ["evasion", "persistence"]
    authors = ["dnsgeeo"]
    minimum = "1.3"
    ttps = ["T1543.003", "T1068"]

    def run(self):
        bd = self.results.get("loldrivers") or {}
        installs = bd.get("service_installs") or []
        if not installs:
            return False
        for s in installs:
            self.data.append(
                {
                    "service_name": s.get("service_name"),
                    "image_path": s.get("image_path"),
                    "service_type": s.get("service_type"),
                    "driver_path": s.get("driver_path"),
                    "driver_sha256": s.get("driver_sha256"),
                    "sample_under_test": s.get("sample_under_test"),
                    "created_by_sample": s.get("created_by_sample"),
                    "creator_name": s.get("creator_name"),
                    "creator_pid": s.get("creator_pid"),
                    "time": s.get("time"),
                }
            )
        return True
