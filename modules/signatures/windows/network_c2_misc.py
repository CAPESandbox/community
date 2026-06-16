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


class SuspiciousHttpTimeouts(Signature):
    name = "suspicious_http_timeouts"
    description = "Sets WinHTTP or WinINet timeouts to unusually low values (<= 10 seconds), possible C2 technique to prevent thread hanging"
    severity = 2
    confidence = 60
    categories = ["c2", "network", "anomaly"]
    authors = ["Kevin Ross", "Gemini"]
    minimum = "1.3"
    evented = True
    ttps = ["T1071.001"]
    mbcs = ["C0002"]

    filter_apinames = {"WinHttpSetTimeouts", "InternetSetOptionA", "InternetSetOptionW"}

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.anomalous_timeouts = []

    def on_call(self, call, process):
        api = call["api"]

        if api == "WinHttpSetTimeouts":
            resolve = self.get_argument(call, "ResolveTimeout")
            connect = self.get_argument(call, "ConnectTimeout")

            try:
                res_val = int(resolve) if resolve else 0
                con_val = int(connect) if connect else 0

                if res_val == 5000 and con_val == 5000:
                    return

                if (0 < res_val <= 10000) or (0 < con_val <= 10000):
                    self.anomalous_timeouts.append({
                        "api": api,
                        "ResolveTimeout": res_val,
                        "ConnectTimeout": con_val
                    })
                    self.mark_call()
                    self.ret = True
            except (ValueError, TypeError):
                pass

        elif api.startswith("InternetSetOption"):
            option = self.get_argument(call, "Option") or self.get_argument(call, "dwOption")
            buffer_val = self.get_argument(call, "Buffer") or self.get_argument(call, "lpBuffer")

            if not option or not buffer_val:
                return

            try:
                opt_val = int(option, 16) if isinstance(option, str) and option.startswith("0x") else int(option)
                
                # 2 = INTERNET_OPTION_CONNECT_TIMEOUT
                # 5 = INTERNET_OPTION_SEND_TIMEOUT
                # 6 = INTERNET_OPTION_RECEIVE_TIMEOUT
                if opt_val in (2, 5, 6):
                    timeout_val = 0
                    
                    if isinstance(buffer_val, str):
                        timeout_val = int(buffer_val, 16) if buffer_val.startswith("0x") else int(buffer_val)
                    elif isinstance(buffer_val, int):
                        timeout_val = buffer_val
                    else:
                        for arg in call.get("arguments", []):
                            if arg.get("name") in ("Buffer", "lpBuffer"):
                                p_val = arg.get("pretty_value", "")
                                if p_val.isdigit():
                                    timeout_val = int(p_val)
                                break

                    if 0 < timeout_val <= 10000:
                        opt_name = "CONNECT_TIMEOUT" if opt_val == 2 else "SEND_TIMEOUT" if opt_val == 5 else "RECEIVE_TIMEOUT"
                        
                        self.anomalous_timeouts.append({
                            "api": api,
                            "Option": opt_name,
                            "Timeout_Ms": timeout_val
                        })
                        self.mark_call()
                        self.ret = True
            except (ValueError, TypeError):
                pass

    def on_complete(self):
        return self.ret
