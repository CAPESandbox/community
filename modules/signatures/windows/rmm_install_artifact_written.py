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

from lib.cuckoo.common.abstracts import Signature


class RMMInstallArtifactWritten(Signature):
    name = "rmm_install_artifact_written"
    description = "RMM tool installation artifact written to a known product-specific path"
    severity = 2
    categories = ["rmm"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttps = ["T1219"]
    references = "https://lolrmm.io/api/rmm_tools.json"

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
        "Bluetrait": [
            r"C:\Program Files (x86)\Bluetrait Agent",
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
            r"C:\Program Files (x86)\Faronics\Deep Freeze\Install C-0",
            r"C:\Program Files (x86)\Faronics\Deep Freeze\Install C-1",
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

    @staticmethod
    def _normalise_path(path):
        """Normalise Windows paths for case-insensitive comparison."""
        return path.replace("/", "\\").rstrip("\\").lower()

    @classmethod
    def _is_under_root(cls, path, root):
        """Return True when path is the root itself or exists below the root."""
        normalised_path = cls._normalise_path(path)
        normalised_root = cls._normalise_path(root)

        return (
            normalised_path == normalised_root
            or normalised_path.startswith(normalised_root + "\\")
        )

    @classmethod
    def _matches_prefix(cls, path, prefix):
        """Return True when a path begins with a known variable RMM path."""
        return cls._normalise_path(path).startswith(cls._normalise_path(prefix))

    def _add_match(self, seen_matches, tool_name, written_file, matched_root):
        """Add a unique RMM match to signature data."""
        match_key = (tool_name, self._normalise_path(written_file))

        if match_key in seen_matches:
            return

        self.data.append(
            {
                "rmm_tool": tool_name,
                "message": "RMM tool '{}' identified".format(tool_name),
                "artifact_type": "installation_artifact",
                "matched_root": matched_root,
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
            # Match fixed product-specific installation roots.
            for tool_name, roots in self.RMM_INSTALL_ROOTS.items():
                for root in roots:
                    if self._is_under_root(written_file, root):
                        self._add_match(
                            seen_matches,
                            tool_name,
                            written_file,
                            root,
                        )
                        matched = True
                        break

            # Match products with variable product-specific installation paths.
            for tool_name, prefixes in self.RMM_INSTALL_PREFIXES.items():
                for prefix in prefixes:
                    if self._matches_prefix(written_file, prefix):
                        self._add_match(
                            seen_matches,
                            tool_name,
                            written_file,
                            prefix,
                        )
                        matched = True
                        break

        return matched

