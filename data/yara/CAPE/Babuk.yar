rule Babuk {
    meta:
        author = "ditekSHen"
        description = "Detects Babuk ransomware"
        cape_type = "Babuk Ransomware Payload"
    strings:
        $s1 = "ecdh_pub_k.bin" wide
        $s2 = ".__NIST_K571__" wide
        $s3 = "How To Restore Your Files.txt" wide
        $s4 = "BY BABUK LOCKER" ascii
        $s5 = "! DANGER !" ascii
        $s6 = "/login.php?id=" ascii
        $s7 = "http://babuk" ascii
        $s8 = "-lanfirst" fullword ascii
        $s9 = "-lansecond" fullword ascii
        $s10 = "-nolan" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of ($s*)
}
