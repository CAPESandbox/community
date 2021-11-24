rule Hive {
    meta:
        author = "ditekSHen"
        description = "Detects Hive ransomware"
        cape_type = "Hive Ransomware Payload"
    strings:
        $url1 = "http://hivecust" ascii
        $url2 = "http://hiveleakdb" ascii
        $s1 = "encrypt_files.go" ascii
        $s2 = "erase_key.go" ascii
        $s3 = "kill_processes.go" ascii
        $s4 = "remove_shadow_copies.go" ascii
        $s5 = "stop_services_windows.go" ascii
        $s6 = "remove_itself_windows.go" ascii
        $x1 = "/encryptor/" ascii
        $x2 = "HOW_TO_DECRYPT.txt" ascii
        $x3 = "FilesEncrypted" fullword ascii
        $x4 = "EncryptionStarted" fullword ascii
        $x5 = "encryptFilesGroup" fullword ascii
        $x6 = "Your data will be undecryptable" ascii
        $x7 = "- Do not fool yourself. Encryption has perfect secrecy" ascii
        $v1_1 = ".EncryptFiles." ascii
        $v1_2 = ".EncryptFilename." ascii
        $v1_3 = ")*struct { F uintptr; .autotmp_14 string }" ascii
        $v1_4 = "D*struct { F uintptr; data *[]uint8; seed *uint8; fnc *main.decFunc }" ascii
        $v1_5 = "golang.org/x/sys/windows.getSystemWindowsDirectory" ascii
        $v1_6 = "path/filepath.WalkDir" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($url*) or all of ($s*) or 4 of ($x*) or 5 of ($v1*))
}
