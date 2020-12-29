rule CryptBot {
    meta:
        author = "ditekSHen"
        description = "CryptBot/Fugrafa stealer payload"
        cape_type = "CryptBot Payload"
    strings:
        $s1 = "Username: %wS" fullword wide
        $s2 = "Computername: %wS" fullword wide
        $s3 = "/c rd /s /q %" wide
        $s4 = "IP: N0t_IP" fullword wide
        $s5 = "Country: N0t_Country" fullword wide
        $s6 = "Content-Type: multipart/form-data; boundary=---------------------------vjHe5u2KxmK2jHn" wide
        $s7 = "Content-Disposition: form-data; name=\"file\"; filename=\"%wS\"" ascii wide

        $f1 = "*ledger*.txt" fullword wide
        $f2 = "*crypto*.xlsx" fullword wide
        $f3 = "*private*.txt" fullword wide
        $f4 = "*wallet*.dat" fullword wide
        $f5 = "*pass*.txt" fullword wide
        $f6 = "*bitcoin*.txt" fullword wide

        $p1 = "\\Files\\_information.txt" fullword wide 
        $p2 = "%USERPROFILE%\\Desktop\\secret.txt" fullword wide 
        $p3 = "%USERPROFILE%\\Desktop\\report.doc" fullword wide

        $v2_1 = "\\_Files\\_Wallet" wide
        $v2_2 = "\\_Files\\_Cookies" wide
        $v2_3 = "\\files_\\cookies\\" wide
        $v2_4 = "\\_Files\\_Files" wide
        $v2_5 = "\\_Files\\_Screen_Desktop.jpeg" wide
        $v2_6 = "\\files_\\screenshot.jpg" wide
        $v2_7 = "[ %wS ]" wide
        $v2_8 = "EXE_PATH:                  %wS" wide
        $v2_9 = "password-check" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((4 of ($s*) and 2 of ($f*) and 1 of ($p*) or (8 of ($v2_*) or (5 of ($v2_*) and 2 of ($s*))))) or (10 of them)
}
