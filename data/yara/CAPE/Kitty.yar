rule Kitty {
    meta:
        author = "ditekSHen"
        description = "Detects Kitty ransomware"
        cape_type = "Kitty Ransomware Payload"
    strings:
        $s1 = "HelloKittyMutex" fullword wide
        $s2 = "-path" fullword wide
        $s3 = "select * from Win32_ShadowCopy" fullword wide
        $s4 = "Win32_ShadowCopy.ID='%s'" fullword wide
        $s5 = "programdata" fullword wide
        $s6 = "$recycle.bin" fullword wide
        $s7 = "read_me_lkd.txt" wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
