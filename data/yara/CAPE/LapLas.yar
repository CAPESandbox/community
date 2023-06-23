rule LapLas {
    meta:
        author = "ditekSHen"
        description = "Detects LapLas Infostealer"
        cape_type = "LapLas Infostealer Payload"
    strings:
        $c1 = "/bot/" ascii
        $c2 = "key=" ascii
        $f1 = "main.isRunning" fullword ascii
        $f2 = "main.writePid" fullword ascii
        $f3 = "main.isStartupEnabled" fullword ascii
        $f4 = "main.enableStartup" fullword ascii
        $f5 = "main.waitOpenClipboard" fullword ascii
        $f6 = "main.clipboardWrite" fullword ascii
        $f7 = "main.setOnline" fullword ascii
        $f8 = "main.getRegex" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((all of ($c*) and 5 of ($f*)) or (1 of ($c*) and 7 of ($f*)))
}
