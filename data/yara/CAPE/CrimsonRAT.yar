rule CrimsonRAT {
    meta:
        author = "ditekSHen"
        description = "Detects CrimsonRAT"
        cape_type = "CrimsonRAT"
    strings:
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|" fullword wide
        $s2 = "system volume information|" fullword wide
        $s3 = "program files (x86)|" fullword wide
        $s4 = "program files|" fullword wide
        $s5 = "<SAVE_AUTO<|" fullword wide
        $s6 = "add_up_files" fullword ascii
        $s7 = "see_folders" fullword ascii
        $s8 = "see_files" fullword ascii
        $s9 = "mainvp" fullword ascii
        $s10 = "machine_procss" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
