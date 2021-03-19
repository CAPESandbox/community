rule Babuk {
    meta:
        author = "ditekSHen"
        description = "Detects Babuk ransomware"
        cape_type = "Babuk Ransomware Payload
    strings:
        $s1 = "ecdh_pub_k.bin" wide
        $s2 = ".__NIST_K571__" wide
        $s3 = "How To Restore Your Files.txt" wide
        $s4 = "BABUK LOCKER" ascii
        $s5 = "! DANGER !" ascii
        $s6 = "/login.php?id=" ascii
        $s7 = "http://babuk" ascii
        $s8 = "babyk ransomware" ascii
        $s9 = "bootsect.bak" fullword wide
        $arg1 = "-lanfirst" fullword ascii
        $arg2 = "-lansecond" fullword ascii
        $arg3 = "-nolan" fullword ascii
        $arg4 = "shares" fullword wide
        $arg5 = "paths" fullword wide
        $arg6 = "gdebug" fullword wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or (3 of ($arg*) and 2 of ($s*)))
}
