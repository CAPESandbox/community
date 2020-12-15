rule RansomEXX {
    meta:
        author = "ditekshen"
        description = "Detects RansomEXX ransomware"
        cape_type = "RansomEXX Payload"
    strings:
        $id = "ransom.exx" ascii
        $s1 = "!TXDOT_READ_ME!.txt" fullword wide
        $s2 = "debug.txt" fullword wide
        $s3 = ".txd0t" fullword wide
        $s4 = "crypt_detect" fullword wide
        $s5 = "powershell.exe" fullword wide
        $s6 = "cipher.exe" fullword ascii wide
        $s7 = "?ReflectiveLoader@@" ascii
    condition:
      uint16(0) == 0x5a4d and (($id and 3 of ($s*)) or all of ($*))
}
