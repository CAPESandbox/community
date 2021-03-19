rule DanaBot {
    meta:
        author = "ditekSHen"
        description = "Detects DanaBot variants"
        cape_type = "DanaBot Payload"
    strings:
        $s1 = "ms ie ftp passwords" fullword wide
        $s2 = "CookieEntryEx_" fullword wide
        $s3 = "winmgmts:\\\\localhost\\root\\cimv2" fullword wide
        $s4 = "S-Password.txt" fullword wide
        $s5 = "del_ini://Main|Password|" fullword wide
        $s6 = "cmd.exe /c start chrome.exe --no-sandbox" wide
        $s7 = "cmd.exe /c start firefox.exe -no-remote" wide
        $s8 = "\\rundll32.exe shell32.dll,#" wide
        $s9 = "S_Error:TORConnect" wide
    condition:
        uint16(0) == 0x5a4d and 7 of them
}
