rule Diavol {
    meta:
        author = "ditekSHen"
        description = "Detect/Hunt for Diavol ransomware"
        cape_type = "Diavol Ransomware Payload"
    strings:
        $s1 = "README_FOR_DECRYPT.txt" ascii wide
        $s2 = ".lock64" fullword ascii wide
        $s3 = "LockMainDIB" ascii wide
        $s4 = "\\locker.divided\\" ascii wide
        $m1 = "GENBOTID" ascii wide
        $m2 = "SHAPELISTS" ascii wide
        $m3 = "REGISTER" ascii wide
        $m4 = "FROMNET" ascii wide
        $m5 = "SERVPROC" ascii wide
        $m6 = "SMBFAST" ascii wide
    condition:
        (uint16(0) == 0x5a4d and all of ($s*)) or 5 of ($m*)
}
