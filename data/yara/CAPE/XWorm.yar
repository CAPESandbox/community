rule XWorm {
    meta:
        author = "ditekSHen"
        description = "Detects XWorm"
        cape_type = "XWorm Payload"
    strings:
        $x1 = "XWorm" wide nocase
        $s1 = "RunBotKiller" fullword wide
        $s2 = "XKlog.txt" fullword wide
        $s3 = /(shell|reg)fuc/ fullword wide
        $s4 = "closeshell" fullword ascii
        $s5 = { 62 00 79 00 70 00 73 00 73 00 00 ?? 63 00 61 00 6c 00 6c 00 75 00 61 00 63 00 00 ?? 73 00 63 00 }
        $s6 = { 44 00 44 00 6f 00 73 00 54 00 00 ?? 43 00 69 00 6c 00 70 00 70 00 65 00 72 00 00 ?? 50 00 45 00 }
        $s7 = { 69 00 6e 00 6a 00 52 00 75 00 6e 00 00 ?? 73 00 74 00 61 00 72 00 74 00 75 00 73 00 62 }
        $s8 = { 48 6f 73 74 00 50 6f 72 74 00 75 70 6c 6f 61 64 65 72 00 6e 61 6d 65 65 65 00 4b 45 59 00 53 50 4c 00 4d 75 74 65 78 78 00 }
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 4 of ($s*)) or 6 of them)
}
