# IsMalicious indicator enrichment for CAPE's threat-intelligence framework.
# See README-ismalicious.md for installation and configuration.

import logging
from urllib.parse import quote

from lib.cuckoo.common.integrations.threatintelligence.base import (
    IND_DOMAIN,
    IND_HASH,
    IND_IP,
    IND_URL,
    IndicatorProvider,
    IntelMatch,
    ProviderResult,
)

log = logging.getLogger(__name__)
API_URL = "https://api.ismalicious.com/check"


class IsMaliciousProvider(IndicatorProvider):
    """Opt-in reputation lookup; risk scores are never used as confidence."""

    name = "ismalicious"
    supported_indicators = {IND_IP, IND_DOMAIN, IND_URL, IND_HASH}

    def __init__(self, options):
        super().__init__(options)
        self.api_key = str(self.options.get("api_key") or "").strip()

    def available(self):
        if not self.api_key:
            return False
        try:
            import requests  # noqa: F401
        except ImportError:
            return False
        return True

    def lookup(self, indicator, indicator_type, ports=None):
        if not self.api_key:
            return ProviderResult(status="disabled")
        if not self.accepts_indicator(indicator_type) or not indicator or not indicator.strip():
            return ProviderResult(status="skipped")

        import requests

        try:
            response = requests.get(
                API_URL,
                params={"query": indicator, "enrichment": "standard"},
                headers={"X-API-KEY": self.api_key, "Accept": "application/json"},
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.Timeout:
            return ProviderResult(status="timeout", error="IsMalicious request timed out")
        except requests.RequestException:
            return ProviderResult(status="error", error="IsMalicious request failed")

        if response.status_code != 200:
            message = "IsMalicious HTTP %s" % response.status_code
            if response.status_code in (401, 403):
                message += "; check the API key and account permissions"
            elif response.status_code == 429:
                message += "; rate limited, retry on a later analysis"
            return ProviderResult(status="error", error=message)
        try:
            payload = response.json()
        except ValueError:
            return ProviderResult(status="error", error="IsMalicious returned invalid JSON")
        if not isinstance(payload, dict) or not isinstance(payload.get("malicious"), bool):
            return ProviderResult(status="error", error="IsMalicious returned an invalid response")
        return self._parse(payload, indicator, indicator_type)

    def _parse(self, payload, indicator, indicator_type):
        evidence = payload.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}
        verdict = evidence.get("verdict")
        if payload.get("lookupStatus") == "unknown":
            return ProviderResult(status="skipped", error="Unknown hash; no safety verdict")
        if payload.get("delisted") is True:
            return ProviderResult(status="no_match")
        if verdict is None and payload.get("malicious") is True:
            verdict = "malicious"
        if verdict != "malicious":
            # no_match means no positive TI match, never that an indicator is safe.
            status = "no_match" if verdict in ("clean", "benign", "suspicious") else "skipped"
            return ProviderResult(status=status)

        confidence = payload.get("confidence") or {}
        score = confidence.get("score") if isinstance(confidence, dict) else None
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 100:
            score = None
        # A configured minimum must not accept an unknown confidence value.
        if self.minimum_confidence and (score is None or score < self.minimum_confidence):
            return ProviderResult(status="skipped", error="Confidence does not meet the configured minimum")

        trust = payload.get("dataTrust") or {}
        if not isinstance(trust, dict):
            trust = {}
        match = IntelMatch(
            source=self.name,
            indicator=indicator,
            indicator_type=indicator_type,
            ioc=indicator,
            ioc_type=indicator_type,
            indicator_url="https://ismalicious.com/report?query=" + quote(indicator, safe=""),
            threat_type="malicious",
            threat_type_desc="; ".join(str(reason) for reason in evidence.get("reasons", [])[:5]),
            confidence_level=score,
            first_seen=trust.get("firstSeen"),
            last_seen=trust.get("lastSeen"),
            tag_category="ismalicious",
            tag_value="malicious",
        )
        result = ProviderResult(status="ok")
        result.matches = [match]
        return result
