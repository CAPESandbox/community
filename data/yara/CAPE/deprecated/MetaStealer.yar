rule MetaStealer {
    meta:
        author = "ditekSHen"
        description = "Detects MetaStealer infostealer"
        cape_type = "MetaStealer Payload"
    strings:
        $s1 = "! #\"'&(&*)>=@?POQOROSOTOUOVOWOXOYOZO[O^]{z|z}z~z" fullword wide
        $s2 = "{0}{1}{2}" fullword wide
        $s3 = "localhost" fullword wide
        $s4 = "\\tdata" fullword wide
        $s5 = "DecryptBlob" fullword ascii
        $s6 = "GetMac" fullword ascii
        $s7 = "GetHdc" fullword ascii
        $s8 = "FindProc" fullword ascii
        $s9 = "targetPid" fullword ascii
        $s10 = "MessageSecurityOverTcp" fullword ascii
        $s11 = "ListOfProcesses" fullword ascii
        $s12 = "ListOfPrograms" fullword ascii
        $s13 = "browserPaths" fullword ascii
        $s14 = "configs" fullword ascii
        $s15 = "scanners" fullword ascii
        $s16 = "FileScannerRule" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 7 of ($s*)
}
