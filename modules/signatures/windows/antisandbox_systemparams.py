# Copyright (C) 2026 Kevin Ross
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

from lib.cuckoo.common.abstracts import Signature


class AntiSandboxSystemParametersInfo(Signature):
    name = "antisandbox_system_parameters_info"
    description = "Queries or modifies system parameters associated with user presence detection or sandbox evasion"
    severity = 2
    confidence = 50
    categories = ["anti-sandbox", "anti-analysis"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1497.001", "T1082"]
    mbcs = ["OB0006", "B0011", "OC0008", "C0065"]

    filter_apinames = set(["SystemParametersInfoW", "SystemParametersInfoA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.user_presence_actions = {
            "0x00000042": "SPI_GETSCREENSAVERRUNNING — queries whether screensaver is currently active (no user present if true)",
            "0x0000000e": "SPI_GETSCREENSAVETIMEOUT — queries idle time before screensaver activates, used to estimate how long machine has been unattended",
            "0x00000010": "SPI_GETSCREENSAVEACTIVE — queries whether screensaver is enabled on this machine",
        }
        self.environment_fingerprint_actions = {
            "0x00000030": "SPI_GETDESKWALLPAPER — queries current desktop wallpaper path; sandboxes commonly have no wallpaper set",
            "0x00000062": "SPI_GETMOUSESPEED — queries mouse pointer speed; default or zero speed is common in sandbox/VM environments",
            "0x0000000a": "SPI_GETKEYBOARDDELAY — queries keyboard auto-repeat delay; may differ from expected value on real machines",
            "0x00000016": "SPI_GETKEYBOARDPREF — queries keyboard preference flag; indicates whether keyboard is preferred over mouse",
            "0x00000060": "SPI_GETWORKAREA — queries usable desktop area; used to fingerprint screen resolution and taskbar configuration",
            "0x0000200a": "SPI_GETCLIENTAREAANIMATION — queries whether UI animations are enabled; often disabled in sandboxes to improve performance",
        }
        self.input_simulation_actions = {
            "0x00000059": "SPI_GETBLOCKSENDINPUTRESETS — queries whether SendInput resets the screensaver timer; used to verify programmatic input simulation behaviour",
        }
        self.manipulation_actions = {
            "0x0000000f": "SPI_SETSCREENSAVETIMEOUT — sets screensaver idle timeout; malware may extend this to prevent screensaver revealing machine is unattended",
            "0x00000011": "SPI_SETSCREENSAVEACTIVE — enables or disables the screensaver; may be disabled to suppress user-presence evidence",
            "0x00000063": "SPI_SETMOUSESPEED — sets mouse pointer speed; may be modified to simulate a non-default user environment",
        }
        self.poll_threshold = 20
        self.user_presence_counts = {}
        self.fingerprint_counts = {}
        self.input_sim_counts = {}
        self.manipulation_hits = {}

    def on_call(self, call, process):
        if not call["status"]:
            return None

        action = (self.get_argument(call, "Action") or "").lower()
        if not action:
            return None

        if action in self.user_presence_actions:
            self.user_presence_counts[action] = self.user_presence_counts.get(action, 0) + 1
            if self.user_presence_counts[action] == self.poll_threshold:
                self.mark_call()

        elif action in self.environment_fingerprint_actions:
            self.fingerprint_counts[action] = self.fingerprint_counts.get(action, 0) + 1
            if self.fingerprint_counts[action] == self.poll_threshold:
                self.mark_call()

        elif action in self.input_simulation_actions:
            self.input_sim_counts[action] = self.input_sim_counts.get(action, 0) + 1
            if self.input_sim_counts[action] == self.poll_threshold:
                self.mark_call()

        elif action in self.manipulation_actions:
            if action not in self.manipulation_hits:
                self.manipulation_hits[action] = 0
                self.mark_call()
            self.manipulation_hits[action] += 1

    def on_complete(self):
        ret = False

        for action, count in self.user_presence_counts.items():
            if count >= self.poll_threshold:
                self.data.append({
                    "technique": "user_presence_detection",
                    "description": self.user_presence_actions[action],
                    "call_count": count,
                })
                ret = True

        for action, count in self.fingerprint_counts.items():
            if count >= self.poll_threshold:
                self.data.append({
                    "technique": "environment_fingerprinting",
                    "description": self.environment_fingerprint_actions[action],
                    "call_count": count,
                })
                ret = True

        for action, count in self.input_sim_counts.items():
            if count >= self.poll_threshold:
                self.data.append({
                    "technique": "input_simulation_detection",
                    "description": self.input_simulation_actions[action],
                    "call_count": count,
                })
                ret = True

        for action, count in self.manipulation_hits.items():
            self.data.append({
                "technique": "environment_manipulation",
                "description": self.manipulation_actions[action],
                "call_count": count,
            })
            ret = True

        return ret
