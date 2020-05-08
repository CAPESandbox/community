rule MassLogger {
    meta:
        author = "ditekshen"
        description = "MassLogger keylogger payload"
        cape_type = "MassLogger payload"
    strings:
        $s1 = "MassLogger v" ascii wide
        $s2 = "MassLogger Started:" ascii wide
        $s3 = "MassLogger Process:" ascii wide
        $s4 = "/panel/upload.php" wide
        $s5 = "ftp://127.0.0.1" fullword wide
        $s6 = "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" fullword wide
        $s7 = "^(.*/)?([^/\\\\.]+/\\\\.\\\\./)(.+)$" fullword wide
        $s8 = "Bot Killer" ascii
        $s9 = "Keylogger And Clipboard" ascii
        $c1 = "costura.ionic.zip.reduced.dll.compressed" fullword ascii
        $c2 = "CHECKvUNIQUEq" fullword ascii
        $c3 = "HOOK/MEMORY6" fullword ascii
        $c4 = "Massfile" ascii wide
        $c5 = "Fz=[0-9]*'skips*" fullword ascii
        $c6 = ":=65535zO" fullword ascii
        $c7 = "!$!%!&!'!(!)!*!.!/!0!4!" fullword ascii
        $c8 = "5!9!:!<!>!@!E!G!J!K!L!N!O!P!`!" fullword ascii
        $c9 = "dllToLoad" fullword ascii
        $c10 = "set_CreateNoWindow" fullword ascii
        $c11 = "FtpWebRequest" fullword ascii
        $c12 = "encryptedUsername" fullword ascii
        $c13 = "encryptedPassword" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 9 of ($c*)) or (5 of ($s*) or 9 of ($c*))
}
