# Copyright 2024 Proofpoint
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from lib.cuckoo.common.abstracts import Signature


class AlienLoaderAPIs(Signature):
    name = "loader_alien"
    description = "Exhibits behavior characteristic of Alien Loader"
    weight = 3
    severity = 3
    categories = ["malware", "loader"]
    families = ["AlienLoader"]
    authors = ["Proofpoint"]
    minimum = "1.3"
    # MITRE v15.1
    # Pikabot payload gets downloaded via HTTPS from the C2 by AlienLoader and a new hidden window is created to start
    # the downloaded payload in a new process after a sleeping time.
    ttps = [
        # Defense Evasion
        "T1497.003",  # Virtualization/Sandbox Evasion - Time Based Evasion
        "T1564"  # Hide Artefacts - Hidden Window
        # Command and Control
        "T1071.001",  # Application Layer Protocol - Web Protocols
    ]
    evented = True

    # Background
    # https://www.virusbulletin.com/conference/vb2024/abstracts/life-and-death-building-detection-forensics-and-intelligence-scale/
    #
    # Sample list
    # 236be07f3d32179f32a7b68d4cf4a67b2aa5b28cce7f51b50cd0e2a5cce1df08
    # 3eabc83a222a1b78ccfb3922ee61040af53efdebd6e654053503965833905164
    # 44a652cb2c75fc104614d83e8f25a35212ce9b4ef1139ac318662eaeeb8ef1b4
    # 473ebefe6a836773895238dc3b1c0553c862e21485ea84e66e2d8a3aa5140542
    # 7fc4d87ed6a8192beac9d8d9f45f44c61dd13e49bfedada43c282198d52dfd38
    # b6ce3ce080856c4b8fffed914d7a3c9d34c4ecd7276be025af717f3c5e6088c5
    # bbef0ad07231eb51263e0d5831ec8f697bb705dc211015cfa4ddbbcd73e2eb4e
    # cc85249e82036e436a538a6d48fa8740f4a4dd56f03b685f67c6b8975ef031ff
    # d409132aff924622527cb36a73afa1ab2afda9aa6c79104b4e364df200f51210
    # d4519a6af1f374516ad25471a6248c689012711f5e0bcc1b09aaf10ceaf20a7f
    # d760bd575c3acf9a9584a6696ae106a9d52be0c0595c5d93409c5a102b155060
    # d8a565ff766d0b7ace95f9fbc3781fc5e06e6c7ad6c40ecf9aa62f7c4ac8ea7b
    # e739217419f83cf7351c18094d5147cf0183bdcee4271b06a75b8b4f7b38766c
    # f20585b7183d6380968b8f1d75a34bb78b6224e5686ebb81430ec14e80fce17a
    # f48433223bf6c59245c1d4086fd23527b5a834730ecebd07ead10b285d711f3f

    filter_apinames = set(["LdrGetProcedureAddress", "send", "NtCreateFile", "NtWriteFile", "CreateProcessInternalW"])
    filter_analysistypes = set(["file"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.hit = False
        self.state = 0
        self.lastprocess = 0
        self.file_name = ""

    def on_call(self, call, process):
        # reset state if new process
        if process != self.lastprocess:
            self.state = 0
            self.lastprocess = process

        # check for Java
        if self.state == 0 and call["api"] == "LdrGetProcedureAddress":
            if self.get_argument(call, "FunctionName") == "JNI_CreateJavaVM":
                self.state = 1

        # connecting to second stage
        elif self.state == 1 and call["api"] == "send":
            self.state = 2

        # creates a file
        elif self.state == 2 and call["api"] == "NtCreateFile":
            name = self.get_argument(call, "FileName")
            if name and name.lower() == "c:\\users\\public\\filename.exe":
                self.file_name = name
                self.state = 3

        # writes file
        elif self.state == 3 and call["api"] == "NtWriteFile":
            handle_name = self.get_argument(call, "HandleName")
            if handle_name and self.file_name in handle_name:
                self.state = 4

        # executes file
        elif self.state == 4 and call["api"] == "CreateProcessInternalW":
            command_line = self.get_argument(call, "CommandLine")
            if command_line and self.file_name.lower() in command_line.lower():
                if self.pid:
                    self.mark_call()
                    self.hit = True
                    return True

        # we've seen sample with offline c2 where we don't see anything else
        elif self.state > 0 and call["api"] == "CreateProcessInternalW" and not call["status"]:
            command_line = self.get_argument(call, "CommandLine")
            if command_line == "c:\\users\\public\\filename.exe":
                if self.pid:
                    self.hit = True
                    self.mark_call()
                    return True

    def on_complete(self):
        return self.hit
