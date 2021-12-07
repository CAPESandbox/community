rule OnlyLogger {
    meta:
        author = "ditekSHen"
        description = "Detects onlyLogger loader variants"
        cape_type = "OnlyLogger Loader"
    strings:
        $s1 = { 45 6c 65 76 61 74 65 64 00 00 00 00 4e 4f 54 20 65 6c 65 76 61 74 65 64 }
        $s2 = "\" /f & erase \"" ascii
        $s3 = "/c taskkill /im \"" ascii
        $s4 = "KILLME" fullword ascii
        $s5 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
        $n1 = "/partner/loot.php?pub=" ascii
        $n2 = "/stats/save.php?pub=" ascii
        $n3 = "/check.php?pub=" ascii
        $n4 = "/stats/off.php?pub=" ascii
        $n5 = "/stats/send.php?trackid=" ascii
        $n6 = "&reason=" ascii
        $n7 = "&postback=" ascii
        $n8 = "?1BEF0A57BE110FD467A" fullword wide
        $gn = ".php?pub=" ascii
        $ip = /\/1[a-z0-9A-Z]{4,5}/ fullword ascii
        //$h1 = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1" fullword ascii
        //$h2 = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8" fullword ascii
        //$h3 = "Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1" fullword ascii
        //$h4 = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0" fullword ascii
        //$h5 = "Content-Type: application/x-www-form-urlencoded" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or 4 of ($n*) or ($gn and #ip > 5) or (2 of ($s*) and 2 of ($n*)))
        //uint16(0) == 0x5a4d and (all of ($s*) or 4 of ($n*) or ($gn and #ip > 5) or (2 of ($s*) and 2 of ($n*)) or (all of ($h*) and 2 of them))
}
