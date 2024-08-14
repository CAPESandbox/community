# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


from lib.cuckoo.common.abstracts import Signature


class Virus(Signature):
    name = "virus"
    description = "Likely virus infection of existing binary"
    severity = 3
    categories = ["virus"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True

    filter_apinames = set(
        [
            "NtCreateFile",
            "NtDuplicateObject",
            "NtOpenFile",
            "NtClose",
            "NtWriteFile",
            "CopyFileA",
            "CopyFileW",
            "CopyFileExA",
            "CopyFileExW",
        ]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = 0
        self.handles = dict()
        self.copydests = set()
        self.readcopyfiles = dict()
        self.readfiles = set()
        self.infected_files = set()
        self.invalidated_files = set()
        self.saw_virus = False

        self.ignorelist = [
            # PowerPoint 2010 frequently overwrites itself for whatever reason
            "powerpnt.exe",
            # Adobe Acrobat Reader 11.0 also overwrites itself
            "acrord32.exe",
        ]

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if call["api"] == "NtDuplicateObject" and call["status"]:
            tgtarg = self.get_argument(call, "TargetHandle")
            if tgtarg:
                srchandle = int(self.get_argument(call, "SourceHandle"), 16)
                tgthandle = int(tgtarg, 16)
                if srchandle in self.handles:
                    self.handles[tgthandle] = self.handles[srchandle]
        elif call["api"].startswith("CopyFile"):
            srcname = self.get_argument(call, "ExistingFileName").lower()
            dstname = self.get_argument(call, "NewFileName").lower()
            self.copydests.add(dstname)
            self.readcopyfiles[dstname] = srcname
            if srcname not in self.invalidated_files and srcname not in self.copydests:
                self.readfiles.add(srcname)
            if dstname in self.readfiles:
                self.infected_files.add(dstname)
                self.saw_virus = True
                if self.pid:
                    self.mark_call()
        elif call["api"] == "NtClose":
            handle = int(self.get_argument(call, "Handle"), 16)
            self.handles.pop(handle, None)
        elif call["api"] == "NtCreateFile" and call["status"]:
            filename = self.get_argument(call, "FileName").lower()
            handle = int(self.get_argument(call, "FileHandle"), 16)
            createdisp = int(self.get_argument(call, "CreateDisposition"), 16)
            if filename and filename.endswith(".exe") and not any(filename.endswith(ignore_exe) for ignore_exe in self.ignorelist):
                if createdisp == 1:
                    if handle not in self.handles and filename not in self.invalidated_files:
                        self.handles[handle] = filename
                else:
                    self.invalidated_files.add(filename)
        elif call["api"] == "NtOpenFile" and call["status"]:
            filename = self.get_argument(call, "FileName").lower()
            handle = int(self.get_argument(call, "FileHandle"), 16)
            if filename and filename.endswith(".exe"):
                if handle not in self.handles and filename not in self.invalidated_files:
                    self.handles[handle] = filename
                    self.readfiles.add(filename)
        elif call["api"] == "NtWriteFile":
            handle = int(self.get_argument(call, "FileHandle"), 16)
            if handle in self.handles:
                key = self.handles[handle]
                if key in self.copydests:
                    key_max_depth = 3
                    while key_max_depth and key in self.readcopyfiles:
                        key = self.readcopyfiles[key]
                        key_max_depth -= 1
                self.infected_files.add(key)
                self.saw_virus = True
                if self.pid:
                    self.mark_call()

        return None

    def on_complete(self):
        for infected in self.infected_files:
            self.data.append({"file": infected})
        return self.saw_virus
