rule RunningRAT {
    meta:
        author = "ditekSHen"
        description = "Detects RunningRAT"
        cape_type = "RunningRAT Payload"
    strings:
        $s1 = "%s%d.dll" fullword ascii
        $s2 = "/c ping 127.0.0.1 -n" ascii
        $s3 = "del /f/q \"%s\"" ascii
        $s4 = "GUpdate" fullword ascii
        $s5 = "%s\\%d.bak" fullword ascii
        $s6 = "\"%s\",MainThread" ascii
        $s7 = "rundll32.exe" fullword ascii
        $rev1 = "emankcosteg" fullword ascii
        $rev2 = "ini.revreS\\" fullword ascii
        $rev3 = "daerhTniaM,\"s%\" s%" ascii
        $rev4 = "s% etadpUllD,\"s%\" 23lldnuR" ascii
        $rev5 = "---DNE yromeMmorFdaoL" fullword ascii
        $rev6 = "eMnigulP" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or all of ($rev*) or 8 of them)
}
