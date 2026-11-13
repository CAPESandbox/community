# Copyright (C) 2026 bartblaze
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
# along with this program. If not, see <https://www.gnu.org/licenses/>.

from fnmatch import fnmatchcase

from lib.cuckoo.common.abstracts import Signature

class RMMConfigurationArtifactWritten(Signature):
    name = "rmm_configuration_artifact_written"
    description = "RMM tool configuration, enrollment, state, or log artifact written. May contain useful indicators"
    severity = 2
    categories = ["rmm"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttps = ["T1219"]
    references = "https://lolrmm.io/api/rmm_tools.json"

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
            r"C:\ProgramData\Getscreen.me\*.gui.log",
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

    @staticmethod
    def _normalise_path(path):
        """Normalise Windows paths for case-insensitive wildcard matching."""
        return path.replace("/", "\\").rstrip("\\").lower()

    @classmethod
    def _matches_configuration_file(cls, written_file, configuration_pattern):
        """Return True when a written file matches a known RMM artifact."""
        normalised_written_file = cls._normalise_path(written_file)
        normalised_configuration_pattern = cls._normalise_path(
            configuration_pattern
        )

        return fnmatchcase(
            normalised_written_file,
            normalised_configuration_pattern,
        )

    def _add_match(
        self,
        seen_matches,
        tool_name,
        configuration_file,
        written_file,
    ):
        """Add a unique artifact match to the signature result."""
        match_key = (
            tool_name,
            self._normalise_path(written_file),
        )

        if match_key in seen_matches:
            return

        self.data.append(
            {
                "rmm_tool": tool_name,
                "message": "RMM tool '{}' identified".format(tool_name),
                "artifact_type": "configuration_or_state",
                "configuration_pattern": configuration_file,
                "written_file": written_file,
            }
        )

        seen_matches.add(match_key)

    def run(self):
        matched = False
        seen_matches = set()

        written_files = (
            self.results.get("behavior", {})
            .get("summary", {})
            .get("write_files", [])
            or []
        )

        for written_file in written_files:
            for tool_name, configuration_files in self.RMM_CONFIGURATION_FILES.items():
                for configuration_file in configuration_files:
                    if self._matches_configuration_file(
                        written_file,
                        configuration_file,
                    ):
                        self._add_match(
                            seen_matches,
                            tool_name,
                            configuration_file,
                            written_file,
                        )
                        matched = True
                        break

        return matched

