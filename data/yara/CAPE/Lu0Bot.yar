rule Lu0Bot {
    meta:
        author = "ditekSHen"
        description = "Detects Lu0Bot"
        cape_type = "Lu0Bot Payload"
    strings:
        $s1 = "WinExec" fullword ascii
        $s2 = "AlignRects" fullword ascii
        $o1 = { be 00 20 40 00 89 f7 89 f0 81 c7 a8 01 00 00 81 }
        $o2 = { 53 50 e8 b0 01 00 00 e9 99 01 00 00 e8 ae 01 00 }
    condition:
        uint16(0) == 0x5a4d and filesize < 4KB and 1 of ($s*) and all of ($o*)
}
