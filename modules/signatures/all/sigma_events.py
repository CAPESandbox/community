from lib.cuckoo.common.abstracts import Signature

SEVERITY_MAP = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}


class SigmaEvents(Signature):
    name = "sigma_events"
    description = "Sigma rule matches detected in Windows Event Logs"
    severity = 1
    confidence = 100
    categories = ["sigma"]
    authors = ["CAPE"]
    enabled = True

    def run(self):
        sigma = self.results.get("sigma", {})
        detections = sigma.get("detections", [])

        if not detections:
            return False

        max_severity = 1
        all_ttps = set()
        stats = sigma.get("statistics", {})

        for i, detection in enumerate(detections):
            level = detection.get("level", "unknown")
            sev = SEVERITY_MAP.get(level, 1)
            if sev > max_severity:
                max_severity = sev

            # Collect MITRE TTPs
            for tech in detection.get("mitre_techniques", []):
                all_ttps.add(tech)

            # Add separator between rules
            if i > 0:
                self.data.append({"---": "---"})

            # Rule header
            title = detection.get("title", "Unknown Rule")
            self.data.append({"Rule": f"{title} [{level.upper()}]"})

            rule_id = detection.get("id", "")
            if rule_id:
                self.data.append({"Sigma ID": rule_id})

            desc = detection.get("description", "")
            if desc:
                self.data.append({"Description": desc})

            count = detection.get("count", 0)
            self.data.append({"Matched Events": str(count)})

            sigma_query = detection.get("sigma_query", "")
            if sigma_query:
                self.data.append({"Sigma Query": sigma_query})

        self.severity = max_severity
        self.ttps = sorted(all_ttps)

        # Update description with stats
        parts = []
        for level in ("critical", "high", "medium", "low", "informational"):
            n = stats.get(level, 0)
            if n > 0:
                parts.append(f"{n} {level}")
        if parts:
            self.description = f"Sigma rule matches: {', '.join(parts)}"

        return True
