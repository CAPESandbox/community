rule SunCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects SunCrypt ransomware"
        cape_type = "SunCrypt Ransomware Payload"
    strings:
        $s1 = "-noshares" fullword wide
        $s2 = "-nomutex" fullword wide
        $s3 = "-noreport" fullword wide
        $s4 = "-noservices" fullword wide
        $s5 = "$Recycle.bin" fullword wide
        $s6 = "YOUR_FILES_ARE_ENCRYPTED.HTML" fullword wide
        $s7 = "\\\\?\\%c:" fullword wide
        $s8 = "locker.exe" fullword ascii
        $s9 = "DllRegisterServer" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}
