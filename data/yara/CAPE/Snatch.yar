rule Snatch {
    meta:
        author = "ditekSHen"
        description = "Detects Snatch / GoRansome ransomware"
        cape_type = "Snatch Ransomware Payload"
    strings:
        $s1 = "main.encryptFile" ascii
        $s2 = "main.encryptFileExt" ascii
        $s3 = "main.deleteShadowCopy" ascii
        $s4 = "main.encodedCommandsList" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}
