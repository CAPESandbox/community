rule BotSh1zoid {
    meta:
        author = "ditekSHen"
        description = "Detects BotSh1zoid"
        cape_type = "BotSh1zoid Payload"
    strings:
        $x1 = "\\BotSh1zoid\\" ascii
        $x2 = "\\BuildPacker.pdb" ascii
        $s1 = "WDefender" fullword ascii
        $s2 = "CheckDefender" fullword ascii
        $s3 = "RunPS" fullword ascii
        $s4 = "DownloadFile" fullword ascii
        $v1_1 = "<Pass encoding=\"base64\">(.*)</Pass>" wide
        $v1_2 = "Grabber\\" wide
        $v1_3 = "/log.php" wide
        $v1_4 = /Browsers\\(Logins|Cards|Cookies)/ wide
        $v1_5 = "<StealSteam>b__" ascii
        $v1_6 = "record_header_field" fullword ascii
        $v1_7 = "JavaScreenshotiptReader" fullword ascii
        $v1_8 = "HTTPDebuggerPro" wide
        $v1_9 = "IEInspector" wide
        $v1_10 = "Fiddler" wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*)) or (7 of ($v1*)))
}
