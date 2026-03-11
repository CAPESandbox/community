# Sigma Detection Integration

CAPEv2 can scan captured EVTX and Sysmon logs against Sigma rules using
[Zircolite](https://github.com/wagga40/Zircolite). Detections appear in the
**Event Logs > Sigma Detections** tab of the analysis report.

## Prerequisites

- Python 3.10+
- CAPEv2 with the `evtx` auxiliary module enabled (collects Windows event logs)
- Sysmon auxiliary module (optional, for additional coverage)

## Installing Zircolite

```bash
# Clone Zircolite and set ownership
sudo git clone https://github.com/wagga40/Zircolite.git /opt/zircolite
sudo chown -R cape:cape /opt/zircolite

# Install dependencies into the CAPEv2 virtualenv
cd /opt/CAPEv2
sudo -u cape poetry run pip install orjson xxhash evtx lxml pysigma \
    pysigma-pipeline-sysmon pysigma-pipeline-windows \
    pysigma-backend-sqlite chardet

# Generate the initial ruleset
cd /opt/zircolite
sudo -u cape poetry --directory /opt/CAPEv2 run python zircolite.py --update-rules

# Copy the generated ruleset to CAPEv2's data directory
sudo -u cape mkdir -p /opt/CAPEv2/data/sigma
sudo -u cape cp /opt/zircolite/rules/rules_windows_generic.json /opt/CAPEv2/data/sigma/
```

## Configuration

### Enable Sigma processing

Add to `conf/processing.conf`:

```ini
[sigma]
enabled = yes
# Path to the Zircolite script
zircolite_path = /opt/zircolite/zircolite.py
# Comma-separated list of Sigma rulesets (relative to CAPEv2 root or absolute paths)
ruleset = data/sigma/rules_windows_generic.json
# Max seconds for Zircolite to run per scan
timeout = 120
# Path to JSON-based filter file (relative to CAPEv2 root or absolute)
filters = data/sigma/filters.json
# Comma-separated Sigma rule UUIDs to suppress globally
# (built-in: d99b79d2-0a6f-4f46-ad8b-260b6e17f982, 100ef69e-3327-481c-8e5c-6d80d9507556
#  which suppress CAPE's own eventlog clearing)
suppress_rule_ids =
# Comma-separated rule titles to suppress globally
suppress_rule_titles = Suspicious Eventlog Clearing or Configuration Change Activity, Potentially Suspicious EventLog Recon Activity Using Log Query Utilities, Start Windows Service Via Net.EXE
```

### Using multiple rulesets

You can specify multiple rulesets separated by commas:

```ini
ruleset = data/sigma/rules_windows_generic.json, data/sigma/rules_custom.json
```

### Per-package rule suppression

Some rules only fire because of how a particular analysis package works.
You can suppress rules for specific packages:

```ini
[sigma_suppress_rules]
# Format: rule_title_or_uuid = package1, package2, ...
# Use * to suppress for all packages
# Examples:
# Suspicious Script Execution From Temp Folder = chrome, edge, chromium
# d99b79d2-0a6f-4f46-ad8b-260b6e17f982 = *
```

### JSON-based filters (advanced)

For more granular control (regex matching on event fields, boolean logic,
per-event vs per-detection scope), edit `data/sigma/filters.json`.

Example filter that suppresses sandbox-caused script launches:

```json
{
    "filters": [
        {
            "comment": "Suppress script launches when parent is sandbox agent",
            "rules": [
                "Suspicious Script Execution From Temp Folder",
                "a6a39bdb-935c-4f0a-ab77-35f4bbf44d33"
            ],
            "packages": ["ps1", "js", "vbs", "hta", "wsf", "batch"],
            "scope": "event",
            "action": "suppress",
            "matches": {
                "sandbox_parent": {
                    "ParentProcessName": {"pattern": "python\\.exe$", "flags": "i"}
                }
            }
        }
    ]
}
```

Filter features:
- **rules**: Match by rule title or Sigma UUID. Use `"*"` to match all rules.
- **packages**: Restrict filter to specific analysis packages (optional).
- **scope**: `"detection"` applies to the whole rule, `"event"` applies per matched event.
- **action**: `"suppress"` removes the detection/event, `"set_score"` overrides the score.
- **matches**: Named groups of regex field matchers.
- **match_logic**: Boolean expression over group names (e.g. `"group1 or (group2 and not group3)"`). Defaults to AND of all groups.
- **flags**: Regex flags per matcher — `i` (case-insensitive), `s` (dotall), `m` (multiline), `n` (negate match).

## Keeping Rules Updated

### Daily automatic updates (systemd timer)

Install the provided systemd units and enable the timer:

```bash
sudo cp /opt/CAPEv2/systemd/cape-sigma-update.service /opt/CAPEv2/systemd/cape-sigma-update.timer /usr/lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cape-sigma-update.timer
```

This runs daily at 03:00, updates rules via `zircolite --update-rules`,
copies them to `data/sigma/`, and restarts `cape-processor.service`.

> **Note**: The service runs as `cape` but restarts `cape-processor` via
> `ExecStartPost`. You may need a polkit rule or sudoers entry to allow
> the `cape` user to restart that service.

### Manual update

```bash
cd /opt/zircolite
sudo -u cape poetry --directory /opt/CAPEv2 run python zircolite.py --update-rules
sudo -u cape cp rules/rules_windows_generic.json /opt/CAPEv2/data/sigma/
sudo systemctl restart cape-processor.service
```

## Verifying It Works

1. Submit a sample for analysis with EVTX collection enabled
2. After processing, check the report's **Event Logs** tab
3. The **Sigma Detections** sub-tab shows matched rules sorted by severity
4. Expand a detection to see the sigma query and matched event details

You can also reprocess an existing task:

```bash
cd /opt/CAPEv2
poetry run python utils/process.py -r <task_id>
```

## Troubleshooting

| Symptom | Check |
|---------|-------|
| No sigma tab in report | Verify `[sigma] enabled = yes` in `processing.conf` |
| "Zircolite not found" in process log | Verify `zircolite_path` points to correct location |
| "No evtx.zip found" | Ensure `evtx` auxiliary module is enabled in `auxiliary.conf` |
| Rules not matching | Check ruleset file exists and is not empty |
| Too many false positives | Add rules to `suppress_rule_titles` or create filters in `filters.json` |
| Processing timeout | Increase `timeout` in `[sigma]` config (default 120s) |
| Filters not suppressing | Check that the package is correctly detected (verify `info.package` in report) |
