# Copyright (C) 2026 CAPE Contributors
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


class ModuleOverloadingMappedViewWithoutName(Signature):
    """
    Detects module overloading via NtMapViewOfSection without module name resolution.

    This signature identifies when a section is mapped into a process but the system
    cannot resolve the module name from the mapped view. This is a strong indicator
    of module overloading or code injection where the mapped section doesn't correspond
    to a legitimate loaded module.

    Malware uses this technique to:
    - Hide injected code from memory scanners
    - Bypass module enumeration tools (e.g., Moneta, PE Sieve)
    - Execute code without a corresponding module entry
    - Implement stealth injection techniques
    """

    name = "module_overloading_mapped_view"
    description = "Detects module overloading via suspicious section mapping without module resolution"
    severity = 3
    confidence = 75
    categories = ["injection", "evasion", "code-injection"]
    authors = ["CAPE Contributors", "Andriy Brukovanskyi"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055", "T1574"]  # Process Injection, Hijack Execution Flow
    mbcs = ["OB0006", "E1055", "E1574"]  # Memory Protection Evasion
    references = [
        "https://en.wikipedia.org/wiki/DLL_injection",
        "https://github.com/hfiref0x/Moneta",
        "https://github.com/hasherezade/pe-sieve"
    ]

    filter_apinames = set(["NtMapViewOfSection", "NtMapViewOfSectionEx"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.suspicious_mappings = []
        self.mapping_count = 0

    def on_call(self, call, process):
        if self.mapping_count > 100:
            # Avoid false positives from legitimate high-frequency mapping
            return False

        # Check if ModuleName field is present in the log
        module_name = self.get_argument(call, "ModuleName")
        section_handle = self.get_argument(call, "SectionHandle")
        base_address = self.get_argument(call, "BaseAddress")

        # When ModuleName is absent or empty, the mapped section has no associated module
        # This is the primary indicator of module overloading/injection
        if not module_name or module_name == "":
            self.suspicious_mappings.append({
                "api": call["api"],
                "section_handle": section_handle,
                "base_address": base_address,
                "offset": self.get_argument(call, "SectionOffset"),
                "view_size": self.get_argument(call, "ViewSize"),
                "protect": self.get_argument(call, "Win32Protect")
            })
            self.mark_call()
            self.mapping_count += 1

            # Flag immediately if we see multiple suspicious mappings
            if len(self.suspicious_mappings) >= 3:
                return True

        return False

    def on_complete(self):
        # Trigger signature if we found suspicious mappings
        return len(self.suspicious_mappings) >= 2


class ModuleOverloadingProtectionChange(Signature):
    """
    Detects modification of protection on mapped memory sections.

    This signature identifies when memory protection is changed on sections that
    were previously mapped without module name resolution. Changing protection
    from PAGE_READONLY to PAGE_EXECUTE_READWRITE on anonymous mapped sections
    indicates injected code being made executable.
    """

    name = "module_overloading_protection_change"
    description = "Detects suspicious protection changes on mapped memory sections"
    severity = 3
    confidence = 70
    categories = ["injection", "evasion"]
    authors = ["CAPE Contributors"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]  # Process Injection
    mbcs = ["OB0006", "E1055"]

    filter_apinames = set(["NtProtectVirtualMemory", "VirtualProtectEx"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.suspicious_protections = []
        self.protection_change_count = 0

    def on_call(self, call, process):
        if self.protection_change_count > 50:
            return False

        new_protection = self.get_argument(call, "NewAccessProtection")
        old_protection = self.get_argument(call, "OldAccessProtection")
        module_name = self.get_argument(call, "ModuleName")
        base_address = self.get_argument(call, "BaseAddress")

        # Detect RWX protection on sections without module names
        # PAGE_EXECUTE_READWRITE = 0x00000040
        if new_protection == "0x00000040":
            if not module_name or module_name == "":
                self.suspicious_protections.append({
                    "api": call["api"],
                    "base_address": base_address,
                    "old_protection": old_protection,
                    "new_protection": new_protection,
                    "size": self.get_argument(call, "NumberOfBytesProtected")
                })
                self.mark_call()
                self.protection_change_count += 1

                if len(self.suspicious_protections) >= 2:
                    return True

        return False

    def on_complete(self):
        return len(self.suspicious_protections) >= 1


class ModuleOverloadingSectionCreation(Signature):
    """
    Detects suspicious section creation with unusual attributes.

    This signature monitors NtCreateSection for patterns associated with module
    overloading, such as sections created with specific allocation attributes
    that are later mapped without a corresponding module.
    """

    name = "module_overloading_section_creation"
    description = "Detects suspicious section creation patterns indicating module overloading"
    severity = 2
    confidence = 60
    categories = ["injection", "evasion"]
    authors = ["CAPE Contributors"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]  # Process Injection
    mbcs = ["OB0006"]

    filter_apinames = set(["NtCreateSection"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.suspicious_sections = []
        self.section_count = 0

    def on_call(self, call, process):
        if self.section_count > 30:
            return False

        # Check for sections created without file association
        # (FileHandle is NULL or not associated with a mapped file)
        file_handle = self.get_argument(call, "FileHandle")
        allocation_attributes = self.get_argument(call, "AllocationAttributes")
        section_page_protect = self.get_argument(call, "SectionPageProtection")

        # SEC_IMAGE_NO_EXECUTE (0x11000000) + PAGE_EXECUTE_* combination
        # is suspicious for module overloading
        if not file_handle or file_handle == "0x00000000":
            # Anonymous sections (no file backing) that are later mapped
            # and given executable permissions are suspicious
            if "0x40" in section_page_protect or "0x20" in section_page_protect:  # PAGE_EXECUTE_*
                self.suspicious_sections.append({
                    "api": call["api"],
                    "allocation_attributes": allocation_attributes,
                    "protection": section_page_protect,
                })
                self.mark_call()
                self.section_count += 1

                if len(self.suspicious_sections) >= 3:
                    return True

        return False

    def on_complete(self):
        return len(self.suspicious_sections) >= 2


class ModuleOverloadingMultipleTechniques(Signature):
    """
    Composite signature detecting multiple module overloading techniques in sequence.

    When section creation, view mapping, and protection changes occur in a specific
    sequence without legitimate module loading, this strongly indicates module overloading.
    """

    name = "module_overloading_multi_technique"
    description = "Detects combination of module overloading techniques"
    severity = 4
    confidence = 85
    categories = ["injection", "evasion"]
    authors = ["CAPE Contributors"]
    minimum = "1.3"
    evented = True
    ttps = ["T1055"]  # Process Injection
    mbcs = ["OB0006", "E1055"]

    filter_apinames = set([
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtMapViewOfSectionEx",
        "NtProtectVirtualMemory",
        "VirtualProtectEx"
    ])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.create_section_count = 0
        self.map_view_without_module = 0
        self.rwx_on_unmapped = 0
        self.api_sequence = []

    def on_call(self, call, process):
        api = call["api"]
        self.api_sequence.append(api)

        # Keep sequence window small
        if len(self.api_sequence) > 20:
            self.api_sequence.pop(0)

        # Track individual activities
        if api == "NtCreateSection":
            self.create_section_count += 1

        elif api in ["NtMapViewOfSection", "NtMapViewOfSectionEx"]:
            module_name = self.get_argument(call, "ModuleName")
            if not module_name or module_name == "":
                self.map_view_without_module += 1
                self.mark_call()

        elif api in ["NtProtectVirtualMemory", "VirtualProtectEx"]:
            new_protect = self.get_argument(call, "NewAccessProtection")
            module_name = self.get_argument(call, "ModuleName")
            if new_protect == "0x00000040" and (not module_name or module_name == ""):
                self.rwx_on_unmapped += 1
                self.mark_call()

        # Detect the overloading pattern: create → map without name → protect RWX
        pattern = [
            "NtCreateSection",
            "NtMapViewOfSection",
            "NtProtectVirtualMemory"
        ]
        sequence_str = ",".join(self.api_sequence[-5:])

        if (self.create_section_count >= 1 and
            self.map_view_without_module >= 1 and
            self.rwx_on_unmapped >= 1):
            return True

        return False

    def on_complete(self):
        # Positive detection if we see the full pattern
        return (self.create_section_count >= 1 and
                self.map_view_without_module >= 2 and
                self.rwx_on_unmapped >= 1)
