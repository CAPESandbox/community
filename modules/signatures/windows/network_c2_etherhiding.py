# Copyright (C) 2026 Kevin Ross, created with assistance from Gemini
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

class EtherHidingSmartContractCall(Signature):
    name = "etherhiding_smart_contract_call"
    description = "Transmitted an Ethereum JSON-RPC command over the network, indicative of retrieving a payload/C2 from a smart contract using EtherHiding"
    severity = 3
    confidence = 100
    categories = ["network", "c2", "defense_evasion"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1102", "T1568"]

    filter_apinames = {
        "HttpSendRequestA", "HttpSendRequestW", 
        "WinHttpSendRequest", "WinHttpWriteData", 
        "InternetWriteFile", "send", "WSASend", "sendto"
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.contract_calls = set()

    def on_call(self, call, process):
        api = call["api"]
        
        # Dynamically grab the payload regardless of which networking API was used
        buffer_data = (
            self.get_argument(call, "PostData") or 
            self.get_argument(call, "Buffer") or 
            self.get_argument(call, "lpBuffer") or 
            self.get_argument(call, "Optional") or 
            self.get_argument(call, "lpOptional")
        )

        if buffer_data and isinstance(buffer_data, str):
            buffer_lower = buffer_data.lower()
            
            # Look for the JSON-RPC payload format
            if '"jsonrpc"' in buffer_lower and '"method"' in buffer_lower:
                if '"eth_call"' in buffer_lower or '"eth_gettransactionbyhash"' in buffer_lower or '"eth_getstorageat"' in buffer_lower:
                    proc_name = process.get("process_name", "unknown")
                    
                    # Truncate buffer to prevent massive strings blowing up the UI
                    event_msg = f"{proc_name} transmitted a smart contract query via {api}: {buffer_data[:150]}..."
                    
                    if event_msg not in self.contract_calls:
                        self.contract_calls.add(event_msg)
                        self.mark_call()
                        self.ret = True

    def on_complete(self):
        if self.ret:
            self.data.append({"etherhiding_contract_queries": list(self.contract_calls)})
        return self.ret
