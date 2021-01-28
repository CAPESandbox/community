rule Thanos {
    meta:
        author = "ditekSHen"
        description = "Detects Thanos ransomware"
        cape_type = "Thanos Ransomware Payload"
    strings:
        $f1 = "<WorkerCrypter2>b__" ascii
        $f2 = "<Encrypt2>b__" ascii
        $f3 = "<Killproc>b__" ascii
        $f4 = "<GetIPInfo>b__" ascii
        $f5 = "<MacAddress>k__" ascii
        $f6 = "<IPAddress>k__" ascii
        $s1 = "Aditional KeyId:" wide
        $s2 = "process call create cmd.exe /c \\\\" wide
        $s3 = "/c rd /s /q %SYSTEMDRIVE%\\$Recycle.bin" wide
        $s4 = "\\HOW_TO_DECYPHER_FILES." wide
        $s5 = "Client Unique Identifier Key:" wide
        $s6 = "/s /f /q c:\\*.VHD c:\\*.bac c:\\*.bak c:\\*.wbcat c:\\*.bkf c:\\Backup*.* c:\\backup*.* c:\\*.set c:\\*.win c:\\*.dsk" fullword wide
        $s7 = "NtOpenProcess" fullword wide
        $s8 = "Builder_Log" fullword wide
        $s9 = "> Nul & fsutil file setZeroData offset=0 length=" wide
        $s10 = "3747bdbf-0ef0-42d8-9234-70d68801f407" // mutex
    condition:
        uint16(0) == 0x5a4d and (all of ($f*) or 5 of ($s*) or 8 of them)
}
