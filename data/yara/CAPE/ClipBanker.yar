rule ClipBanker {
    meta:
        author = "ditekSHen"
        description = "Detects ClipBanker infostealer"
        cape_type = "ClipBanker Payload"
    strings:
        $s1 = "Clipper" fullword wide
        $s2 = "Ushell" fullword wide
        $s3 = "Banker" fullword wide
        $s4 = "ClipPurse" fullword wide nocase
        $s5 = "SelfClip" fullword wide
        $s6 = "Cliper" fullword wide
        $s7 = "FHQD4313-33DE-489D-9721-6AFF69841DEA" fullword wide
        $s8 = "Remove.bat" fullword wide
        $s9 = "\\w{1}\\d{12}" fullword wide
        $s10 = "SELECT * FROM Win32_ComputerSystem" fullword wide
        $s11 = "red hat" fullword wide
        $s12 = { 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00
                 2e 00 65 00 78 00 65 00 00 ?? 2f 00 63 00 72 00
                 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00
                 20 00 00 ?? 20 00 2f 00 6d 00 6f 00 20 00 00 ??
                 20 00 2f 00 72 00 6c 00 20 00 00 ?? 20 00 2f 00
                 74 00 6e 00 20 00 00 ?? 20 00 2f 00 74 00 72 00
                 20 00 00 ?? 20 00 ?? 00 ?? 00 00 ?? 2f 00 64 00
                 65 00 6c 00 65 00 74 00 65 00 20 00 2f 00 74 00
                 6e }
        $s13 = "ClipChanger" fullword ascii
        $s14 = "CheckVirtual" fullword ascii
        $s15 = "InjReg" fullword ascii
        $s16 = "SuicideFile" fullword ascii
        $s17 = "HideFile" fullword ascii
        $s18 = "AntiVm" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 7 of them
}
