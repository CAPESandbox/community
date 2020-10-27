rule CryptBot {
    meta:
        author = "ditekshen"
        description = "CryptBot/Fugrafa stealer payload"
        cape_type = "CryptBot Payload"
    strings:
        $s1 = "Username: %wS" fullword wide
        $s2 = "Computername: %wS" fullword wide
        $s3 = "/c rd /s /q %ProgramData%\\" wide
        $s4 = "IP: N0t_IP" fullword wide
        $s5 = "Country: N0t_Country" fullword wide
        $s6 = "Content-Type: multipart/form-data; boundary=---------------------------vjHe5u2KxmK2jHn" wide
        $s7 = "Content-Disposition: form-data; name=\"file\"; filename=\"%wS\"" wide

        $f1 = "*ledger*.txt" fullword wide
        $f2 = "*crypto*.xlsx" fullword wide
        $f3 = "*private*.txt" fullword wide
        $f4 = "*wallet*.dat" fullword wide
        $f5 = "*pass*.txt" fullword wide
        $f6 = "*bitcoin*.txt" fullword wide

        $p1 = "\\Files\\_information.txt" fullword wide 
        $p2 = "%USERPROFILE%\\Desktop\\secret.txt" fullword wide 
        $p3 = "%USERPROFILE%\\Desktop\\report.doc" fullword wide 
    condition:
        uint16(0) == 0x5a4d and ((4 of ($s*) and 2 of ($f*) and 1 of ($p*)) or (10 of them))
}
