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
        $s6 = "password-check" fullword ascii
        $s7 = "Content-Disposition: form-data; name=\"file\"; filename=\"%wS\"" ascii wide
        $s8 = "[ %wS ]" wide
        $s9 = "EXE_PATH:                  %wS" wide
        $s10 = "Username (Computername):   %wS" wide
        $s11 = "Operating system language: %wS" wide
        $f1 = "*ledger*.txt" fullword wide
        $f2 = "*crypto*.xlsx" fullword wide
        $f3 = "*private*.txt" fullword wide
        $f4 = "*wallet*.dat" fullword wide
        $f5 = "*pass*.txt" fullword wide
        $f6 = "*bitcoin*.txt" fullword wide
        $p1 = "%USERPROFILE%\\Desktop\\*.txt" fullword wide
        $p2 = "%USERPROFILE%\\Desktop\\secret.txt" fullword wide 
        $p3 = "%USERPROFILE%\\Desktop\\report.doc" fullword wide
        $pattern = /\\(files_|_Files)\\(_?)(cookies|cryptocurrency|forms|passwords|system_info|screenshot|screen_desktop|information|files|wallet|cc)\\?(\.txt|\.jpg|\.jpeg)?/ ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and ((5 of ($s*) and 1 of ($p*)) or (4 of ($s*) and 1 of ($f*) and 1 of ($p*)) or  (#pattern > 6 and (2 of ($s*) or 1 of ($p*))))
}
