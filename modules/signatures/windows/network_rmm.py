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
from fnmatch import fnmatchcase
from functools import lru_cache
from urllib.parse import urlsplit

from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.common.constants import CUCKOO_ROOT

DOMAINS_FILE = os.path.join(CUCKOO_ROOT, "data", "rmm_domains.txt")


def normalize_domain(value):
    """Normalise a hostname for case-insensitive comparisons."""
    if not isinstance(value, str):
        return ""

    return value.strip().lower().rstrip(".")


@lru_cache(maxsize=1)
def load_domains():
    domains = set()

    try:
        with open(DOMAINS_FILE, encoding="utf-8") as handle:
            for line in handle:
                # Support empty lines, full-line comments, and inline comments.
                domain = line.split("#", 1)[0].strip()

                if domain:
                    domains.add(normalize_domain(domain))
    except OSError:
        return frozenset()

    return frozenset(domains)


def match_domain(observed_domain, listed_domains):
    """Return the longest matching listed domain suffix in O(labels) lookups."""
    observed_domain = normalize_domain(observed_domain)

    if not observed_domain or not listed_domains:
        return None

    labels = observed_domain.split(".")
    for idx in range(len(labels)):
        candidate = ".".join(labels[idx:])
        if candidate in listed_domains:
            return candidate

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


def normalise_win_path(path):
    """Normalise Windows paths for case-insensitive comparison."""
    if not isinstance(path, str):
        return ""

    return path.replace("/", "\\").rstrip("\\").lower()


class NetworkDnsRmm(Signature):
    name = "network_dns_rmm"
    description = "Resolves a known remote access, RMM, or tunnelling service domain"
    severity = 2
    confidence = 60
    categories = ["network", "rmm"]
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
    categories = ["network", "rmm"]
    authors = ["bartblaze"]
    minimum = "2.0"
    evented = True
    ttps = ["T1219"]
    ttps += ["T1219.002"]
    references = [
        "https://lolrmm.io/api/rmm_tools.json",
        "bartblaze",
    ]

    filter_apinames = {
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "URLDownloadToCacheFileA",
        "URLDownloadToCacheFileW",
    }

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


class RMMArtifactWritten(Signature):
    name = "rmm_artifact_written"
    description = "RMM tool installation, configuration, enrollment, state, or log artifact written"
    severity = 2
    categories = ["rmm"]
    authors = ["bartblaze"]
    minimum = "2.0"
    ttps = ["T1219"]
    ttps += ["T1219.002"]
    references = [
        "https://lolrmm.io/api/rmm_tools.json",
        "bartblaze",
    ]

    RMM_CONFIGURATION_FILES = {
        "Beacon (Synertek)": [
            r"C:\ProgramData\Beacon\credential.json",
            r"C:\ProgramData\Beacon\agent.log",
        ],
        "Bluetrait": [
            r"C:\Program Files (x86)\Bluetrait Agent\config.db",
            r"C:\Program Files (x86)\Bluetrait Agent\config.json",
        ],
        "Borealis": [
            r"C:\Borealis\agent.json",
            r"C:\Borealis\Logs\Agent\agent.log",
        ],
        "ControlR": [
            r"C:\ProgramData\ControlR\*\appsettings.json",
            r"C:\ProgramData\ControlR\*\Logs\ControlR.Agent\LogFile*.log",
            r"C:\ProgramData\ControlR\*\Logs\ControlR.DesktopClient\LogFile*.log",
        ],
        "Faronics Deploy": [
            r"C:\ProgramData\Faronics\StorageSpace\FWA\CloudAgentLogs.LOG",
            r"C:\ProgramData\Faronics\StorageSpace\FWA\Logs\FWASvc.log",
        ],
        "Getscreen": [
            r"C:\ProgramData\Getscreen.me\settings.dat",
            r"C:\ProgramData\Getscreen.me\session.inf",
            r"C:\ProgramData\Getscreen.me\*.log",
        ],
        "GLPI Agent": [
            r"C:\Program Files\GLPI-Agent\etc\agent.cfg",
            r"C:\Program Files\GLPI-Agent\logs\glpi-agent.log",
        ],
        "Go Mini RMM": [
            r"C:\rmm\config.json",
        ],
        "MeshCentral": [
            r"C:\Program Files\Mesh Agent\MeshAgent.msh",
        ],
        "NetBird": [
            r"C:\ProgramData\Netbird\config.json",
        ],
        "NetMaster": [
            r"C:\ProgramData\NetMaster\config.ini",
            r"C:\ProgramData\NetMaster\log.txt",
        ],
        "Obliance": [
            r"C:\ProgramData\OblianceAgent\config.json",
            r"C:\ProgramData\OblianceAgent\agent.log",
            r"C:\ProgramData\OblianceAgent\watchdog.json",
        ],
        "OpenUEM": [
            r"C:\Program Files\OpenUEM Agent\config\openuem.ini",
            r"C:\Program Files\OpenUEM Agent\logs\openuem-log.txt",
        ],
        "OpsBridge": [
            r"C:\ProgramData\OpsBridge\agent_state.json",
            r"C:\ProgramData\OpsBridge\agent.log",
            r"C:\ProgramData\OpsBridge\install.log",
            r"C:\ProgramData\OpsBridge\.persisted_v4",
            r"C:\ProgramData\OpsBridge\task_*.json",
        ],
        "ProxiPort": [
            r"C:\Program Files\ProxiPort\proxiport.conf",
        ],
        "RemotePC": [
            r"C:\Program Files (x86)\RemotePC\Register.reg",
        ],
        "Remotely": [
            r"C:\Program Files\Remotely\ConnectionInfo.json",
            r"C:\Program Files\Remotely\etag.txt",
        ],
        "Roster": [
            r"C:\ProgramData\Roster\agent.yaml",
            r"C:\ProgramData\Roster\agent-state.json",
        ],
        "SetMe": [
            r"C:\ProgramData\Techinline Ltd\settings.ini*",
        ],
        "Splashtop": [
            r"C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\db\SRAgent.sqlite3",
            r"C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\agent_log.txt",
            r"C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\SPLog.txt",
            r"C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\svcinfo.txt",
            r"C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\sysinfo.txt",
        ],
        "Veyon": [
            r"C:\Windows\Temp\VeyonServer.log",
            r"C:\Windows\Temp\VeyonService.log",
        ],
        "Zecurit": [
            r"C:\Program Files\Zecurit\Agent\Storage\AgentSettings.json",
            r"C:\Program Files\Zecurit\Agent\Logs\agent_service.log",
            r"C:\Program Files\Zecurit\Agent\Logs\agent_cmd_handler.log",
        ],
    }

    RMM_INSTALL_ROOTS = {
        "Action1": [
            r"C:\Windows\Action1",
        ],
        "AnyDesk": [
            r"C:\Program Files\AnyDesk",
            r"C:\Program Files (x86)\AnyDesk",
        ],
        "AnyViewer": [
            r"C:\Program Files (x86)\AnyViewer",
        ],
        "Atera": [
            r"C:\Program Files\ATERA Networks\AteraAgent",
            r"C:\Program Files (x86)\ATERA Networks\AteraAgent",
            r"C:\Program Files\Atera Networks",
            r"C:\Program Files (x86)\Atera Networks",
        ],
        "Baramundi Management Suite": [
            r"C:\Program Files\bsag",
            r"C:\Program Files (x86)\bsag",
        ],
        "Beacon (Synertek)": [
            r"C:\ProgramData\Beacon",
        ],
        "Bluetrait": [
            r"C:\Program Files (x86)\Bluetrait Agent",
        ],
        "Borealis": [
            r"C:\Borealis",
        ],
        "BreezeRMM": [
            r"C:\Program Files\Breeze",
            r"C:\ProgramData\Breeze",
        ],
        "Chrome Remote Desktop": [
            r"C:\Program Files (x86)\Google\Chrome Remote Desktop",
        ],
        "ConnectWise Automate / LabTech": [
            r"C:\Program Files (x86)\LabTech",
        ],
        "ControlR": [
            r"C:\Program Files\ControlR",
            r"C:\ProgramData\ControlR",
        ],
        "Faronics Core": [
            r"C:\Program Files\Faronics\Faronics Core",
            r"C:\Program Files (x86)\Faronics\Faronics Core",
        ],
        "Faronics Deep Freeze": [
            r"C:\Program Files\Faronics\Deep Freeze",
            r"C:\Program Files (x86)\Faronics\Deep Freeze",
        ],
        "Faronics Deploy": [
            r"C:\Program Files (x86)\Faronics\Faronics Deploy Agent",
            r"C:\ProgramData\Faronics\StorageSpace\FWA",
        ],
        "Faronics Insight": [
            r"C:\Program Files\Faronics\Insight Student",
            r"C:\Program Files\Faronics\Insight Teacher",
            r"C:\Program Files (x86)\Faronics\Insight Student",
            r"C:\Program Files (x86)\Faronics\Insight Teacher",
        ],
        "FleetDeck": [
            r"C:\Program Files (x86)\FleetDeck Agent",
            r"C:\Windows\Temp\FleetDeck",
        ],
        "Getscreen": [
            r"C:\Program Files\Getscreen.me",
            r"C:\ProgramData\Getscreen.me",
        ],
        "GLPI Agent": [
            r"C:\Program Files\GLPI-Agent",
        ],
        "Go Mini RMM": [
            r"C:\rmm",
        ],
        "GoTo Resolve": [
            r"C:\Program Files\GoTo Resolve Unattended",
            r"C:\Program Files (x86)\GoTo Resolve Unattended",
        ],
        "Gorelo RMM": [
            r"C:\Program Files\Gorelo",
        ],
        "Goverlan": [
            r"C:\Program Files (x86)\PJ Technologies\GOVsrv",
        ],
        "HeartbeatRM": [
            r"C:\Program Files\HeartbeatRM",
            r"C:\Program Files (x86)\HeartbeatRM",
        ],
        "HopToDesk": [
            r"C:\Program Files (x86)\HopToDesk",
        ],
        "ImmyBot": [
            r"C:\Program Files\ImmyBot",
            r"C:\Program Files (x86)\ImmyBot",
            r"C:\ProgramData\ImmyBot",
            r"C:\ProgramData\ImmyBotAgentService",
        ],
        "ISL Online / ISL Light": [
            r"C:\Program Files (x86)\ISL Online",
        ],
        "Kaseya VSA": [
            r"C:\Program Files (x86)\Kaseya",
            r"C:\ProgramData\Kaseya",
        ],
        "Lavawall": [
            r"C:\Program Files\Lavawall",
            r"C:\Program Files (x86)\Lavawall",
            r"C:\Lavawall",
        ],
        "ManageEngine Desktop Central": [
            r"C:\Program Files (x86)\DesktopCentral_Agent",
        ],
        "ManageEngine ServiceDesk Plus": [
            r"C:\Program Files\ManageEngine\ServiceDesk",
            r"C:\Program Files (x86)\ManageEngine\ServiceDesk",
        ],
        "MeshCentral": [
            r"C:\Program Files\Mesh Agent",
        ],
        "Monitic": [
            r"C:\Program Files\Monitic",
        ],
        "NetBird": [
            r"C:\Program Files\Netbird",
            r"C:\ProgramData\Netbird",
        ],
        "NetLock RMM": [
            r"C:\ProgramData\0x101 Cyber Security\NetLock RMM",
            r"C:\Program Files\0x101 Cyber Security\NetLock RMM",
        ],
        "NetMaster": [
            r"C:\ProgramData\NetMaster",
        ],
        "NinjaOne / NinjaRMM": [
            r"C:\ProgramData\NinjaRMMAgent",
        ],
        "Obliance": [
            r"C:\Program Files\OblianceAgent",
            r"C:\ProgramData\OblianceAgent",
        ],
        "OpenUEM": [
            r"C:\Program Files\OpenUEM Agent",
        ],
        "OpsBridge": [
            r"C:\Program Files\OpsBridge",
            r"C:\ProgramData\OpsBridge",
        ],
        "Parsec": [
            r"C:\Program Files\Parsec",
        ],
        "PDQ Connect": [
            r"C:\ProgramData\PDQ\PDQConnectAgent",
        ],
        "ProxiPort": [
            r"C:\Program Files\ProxiPort",
        ],
        "RemotePC": [
            r"C:\Program Files (x86)\RemotePC",
        ],
        "RemotePulse": [
            r"C:\Program Files (x86)\RemotePulseAgent",
        ],
        "Remotely": [
            r"C:\Program Files\Remotely",
        ],
        "RMMmax": [
            r"C:\ProgramData\rmmmax\AgentService",
        ],
        "Roster": [
            r"C:\Program Files\Roster",
            r"C:\ProgramData\Roster",
        ],
        "SetMe": [
            r"C:\Program Files (x86)\Techinline Ltd\SetMe Unattended",
            r"C:\ProgramData\SetMe Client",
            r"C:\ProgramData\Techinline Ltd",
        ],
        "Splashtop": [
            r"C:\Program Files (x86)\Splashtop",
            r"C:\ProgramData\Splashtop",
        ],
        "Tactical RMM": [
            r"C:\Program Files\Tactical RMM",
            r"C:\ProgramData\Tactical RMM",
        ],
        "TeamViewer": [
            r"C:\Program Files\TeamViewer",
        ],
        "Veyon": [
            r"C:\Program Files\Veyon",
            r"C:\Program Files (x86)\Veyon",
        ],
        "Zecurit": [
            r"C:\Program Files\Zecurit\Agent",
            r"C:\Windows\Temp\Zecurit",
        ],
    }

    RMM_INSTALL_PREFIXES = {
        "ScreenConnect": [
            r"C:\Program Files (x86)\ScreenConnect Client (",
            r"C:\ProgramData\ScreenConnect Client",
        ],
    }

    _EXACT_CONFIG_MAP = {
        normalise_win_path(pattern): (tool_name, pattern)
        for tool_name, patterns in RMM_CONFIGURATION_FILES.items()
        for pattern in patterns
        if "*" not in pattern and "?" not in pattern
    }

    _GLOB_CONFIG_LIST = tuple(
        (tool_name, pattern, normalise_win_path(pattern))
        for tool_name, patterns in RMM_CONFIGURATION_FILES.items()
        for pattern in patterns
        if "*" in pattern or "?" in pattern
    )

    _NORM_INSTALL_ROOTS = tuple(
        (tool_name, root, normalise_win_path(root), normalise_win_path(root) + "\\")
        for tool_name, roots in RMM_INSTALL_ROOTS.items()
        for root in roots
    )

    _NORM_INSTALL_PREFIXES = tuple(
        (tool_name, prefix, normalise_win_path(prefix))
        for tool_name, prefixes in RMM_INSTALL_PREFIXES.items()
        for prefix in prefixes
    )

    def _add_match(self, seen_matches, tool_name, artifact_type, matched_pattern, written_file, norm_file):
        """Add a unique RMM artifact match to signature data."""
        match_key = (tool_name, norm_file)
        if match_key in seen_matches:
            return

        seen_matches.add(match_key)
        self.data.append(
            {
                "rmm_tool": tool_name,
                "message": f"RMM tool '{tool_name}' identified",
                "artifact_type": artifact_type,
                "matched_pattern": matched_pattern,
                "written_file": written_file,
            }
        )

    def _match_written_file(self, written_file, norm_file, seen_matches):
        exact_match = self._EXACT_CONFIG_MAP.get(norm_file)
        if exact_match:
            tool_name, pattern = exact_match
            self._add_match(seen_matches, tool_name, "configuration_or_state", pattern, written_file, norm_file)
            return

        for tool_name, pattern, norm_pattern in self._GLOB_CONFIG_LIST:
            if fnmatchcase(norm_file, norm_pattern):
                self._add_match(seen_matches, tool_name, "configuration_or_state", pattern, written_file, norm_file)
                return

        for tool_name, root, norm_root, norm_root_slash in self._NORM_INSTALL_ROOTS:
            if norm_file == norm_root or norm_file.startswith(norm_root_slash):
                self._add_match(seen_matches, tool_name, "installation_artifact", root, written_file, norm_file)
                return

        for tool_name, prefix, norm_prefix in self._NORM_INSTALL_PREFIXES:
            if norm_file.startswith(norm_prefix):
                self._add_match(seen_matches, tool_name, "installation_artifact", prefix, written_file, norm_file)
                return

    def run(self):
        seen_matches = set()
        written_files = self.results.get("behavior", {}).get("summary", {}).get("write_files", []) or []

        for written_file in written_files:
            norm_file = normalise_win_path(written_file)
            if not norm_file:
                continue

            self._match_written_file(written_file, norm_file, seen_matches)

        return bool(seen_matches)
