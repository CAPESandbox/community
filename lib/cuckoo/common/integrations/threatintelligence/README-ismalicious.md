# IsMalicious indicator provider

This optional provider uses the IsMalicious `/check` API to enrich IPs, domains,
full URLs and hashes with a positive malicious indicator match, reasons,
confidence and a report link. It requires CAPE's threat-intelligence framework
(introduced in CAPEv2 PR #3133) and an IsMalicious account/API key.

Individual API checks have account quotas. This provider performs individual
lookups, not TAXII feed ingestion. See [API documentation](https://ismalicious.com/api-docs).

## Install

Install the community `integrations` category with CAPE's `utils/community.py`
or copy `ismalicious_provider.py` into
`lib/cuckoo/common/integrations/threatintelligence/` in the CAPE checkout.
Review `utils/community.py --help` before installing community files.

Register the provider by adding this entry to `_INDICATOR_MODULES` in
`lib/cuckoo/common/integrations/threatintelligence/registry.py`:

```python
"ismalicious": "lib.cuckoo.common.integrations.threatintelligence.ismalicious_provider.IsMaliciousProvider",
```

Add this section to the local `conf/threat_intel.conf` (keep credentials out of Git):

```ini
[ismalicious]
enabled = yes
api_key = <BASE64_ENCODED_APIKEY_COLON_APISECRET>
timeout = 25
minimum_confidence = 0
```

The `api_key` setting is the complete `X-API-KEY` credential: Base64 of
`apiKey:apiSecret`, available from your account. It is not the raw API key
alone. Keep the encoded credential secret.

Enable `[threatintelligence]` in `conf/processing.conf`. Select indicator types
in the global `[threatintelligence]` section of `conf/threat_intel.conf`.
Keep `promote_to_detection = no` unless your team separately validates a policy
for promotion. URLs and submitted SHA256 lookups are off by default in CAPE.

## Interpretation

- The server's `evidence.verdict` must be `malicious` to emit a match. For older
  responses without `evidence`, only explicit `malicious: true` emits a match.
- `malicious: false` is not a safety verdict. Unknown hashes remain skipped,
  and reviewed/delisted indicators produce no match.
- Confidence is `confidence.score`; risk score is a different concept. Missing
  confidence stays `None`. A nonzero `minimum_confidence` excludes missing confidence.
- Context source rows are not counted as detections, and no malware-family or
  threat-actor attribution is invented.
- Errors, invalid responses, authentication failures, rate limits and timeouts
  remain errors/skipped outcomes. They are not cached as successful clean results.
- Queries go only to the configured provider endpoint, with TLS verification,
  encoded parameters and redirects disabled. Full URLs can contain sensitive
  tokens; enabling URL lookups is an explicit analyst configuration decision.

The normal CAPE threat-intelligence processor renders matches in its network
report and retains provider attribution. This community file does not overwrite
CAPE's registry or configuration automatically. Test in a staging CAPE instance
before enabling it for production analyses.

## Tests

From a CAPE checkout containing this provider and the community test file:

```sh
python -m unittest discover -s tests -p 'test_ismalicious_provider.py' -v
```

Tests use synthetic responses and mock the HTTP client. No API key or network
access is required. End-to-end CAPE report rendering is a separate deployment
check.
