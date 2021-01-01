rule QnapCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects QnapCrypt/Lockedv1 ransomware"
        cape_type = "QnapCrypt Payload"
    strings:
        $go = "Go build ID:" ascii
        $s1 = "Encrypting %s..." ascii
        $s2 = "\\Start Menu\\Programs\\StartUp\\READMEV" ascii
        $s3 = "main.deleteRecycleBin" ascii
        $s4 = "main.encryptFiles" ascii
        $s5 = "main.antiVirtualBox" ascii
        $s6 = "main.antiVmware" ascii
        $s7 = "main.deleteShadows" ascii
        $s8 = "main.delUAC" ascii
        $s9 = ".lockedv1" ascii
    condition:
        uint16(0) == 0x5a4d and $go and 6 of ($s*)
}
