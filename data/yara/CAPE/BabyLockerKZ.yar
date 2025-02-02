rule BabyLockerKZ {
    meta:
        author = "ditekshen"
        description = "Detects BabyLockerKZ"
        cape_type = "BabyLockerKZ Payload"
    strings:
        $s1 = ":\\locker\\bin\\stub_win_x64_encrypter.pdb" ascii
        $s2 = "taskkill /f /im explorer.exe" fullword wide
        $s3 = "\\SysWOW64\\cmd.exe /c %windir%\\" wide
        $s4 = "[!] Failed to RunNonElevated: %s, error 0x%X" fullword wide
        $s5 = "[!] Failed to run sync command: %s, error 0x%X" fullword wide
        $s6 = "[-] RunNonElevated: %s" fullword wide
        $s7 = "[!][Encrypt] Not" fullword
        $s8 = "[-] sALLUSERSPROFILE: %s" fullword wide
        $s9 = "[!] WNetGetConnection failed 0x%X" fullword wide
        $s10 = "[!][Scan] " wide
        $s11 = "[-] Start encrypt" wide
    condition: 
        uint16(0) == 0x5a4d and 4 of them
}
