# Copyright (C) 2026 Kevin Ross
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
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class SimilarityMatch(Signature):
    name = "similarity_match"
    description = "Code or structural similarity match to a malware family"
    severity = 3
    confidence = 50
    categories = ["similarity", "malware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = False

    def run(self):
        # Access the similarity section from the generated report
        similarity = self.results.get("similarity")
        if not isinstance(similarity, dict):
            return self.ret

        by_sha256 = similarity.get("by_sha256") or {}
        if not isinstance(by_sha256, dict):
            return self.ret

        seen = set()
        for artifact_sha, matches in by_sha256.items():
            if not isinstance(matches, list):
                continue
                
            for m in matches:
                if not isinstance(m, dict):
                    continue
                    
                family = m.get("family")
                if not family or family == "unknown":
                    continue
                    
                try:
                    sim = float(m.get("similarity") or 0.0)
                except (TypeError, ValueError):
                    sim = 0.0
                    
                # Threshold check: skip low scores and explicit low_confidence flags
                if sim < 50.0 or m.get("low_confidence"):
                    continue

                engine = m.get("engine", "mcrit")
                sample = m.get("sample_sha256", "unknown")
                
                key = (family.lower(), sample, engine)
                if key in seen:
                    continue
                seen.add(key)
                
                match_line = (
                    f"matched_family = {family} "
                    f"similarity_score = {round(sim, 2)} "
                    f"engine = {engine} "
                    f"artifact_sha256 = {artifact_sha} "
                    f"matched_sample = {sample} "
                    f"matched_functions = {m.get('matched_functions', 0)} "
                    f"total_functions = {m.get('total_functions', 0)}"
                )
                
                self.data.append({"match_summary": match_line})
                self.ret = True

        return self.ret
