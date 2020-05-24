rule Orion {
    meta:
        author = "ditekshen"
        description = "Orion Keylogger payload"
        cape_type = "Orion payload"
    strings:
        $s1 = "\\Ranger.BrowserLogging" ascii wide
        $s2 = "GrabAccounts" fullword ascii
        $s3 = "DownloadFile" fullword ascii
        $s4 = "Internet Explorer Recovery" wide
        $s5 = "Outlook Recovery" wide
        $s6 = "Thunderbird Recovery" wide
        $s7 = "Keylogs -" wide
        $s8 = "WebCam_Capture.dll" wide
    condition:
        (uint16(0) == 0x5a4d and 5 of ($s*)) or (6 of ($s*))
}
