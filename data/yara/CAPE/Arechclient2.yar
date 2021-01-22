rule Arechclient2 {
    meta:
        author = "ditekSHen"
        description = "Detects Arechclient2 RAT"
        cape_type = "Arechclient2 Payload"
    strings:
        $s1 = "\\Google\\Chrome\\User Data\\copiedProf\"" wide
        $s2 = "\",\"BotName\":\"" wide
        $s3 = "\",\"BotOS\":\"" wide
        $s4 = "\",\"URLData\":\"" wide
        $s5 = "{\"Type\":\"ConnectionType\",\"ConnectionType\":\"Client\",\"SessionID\":\"" wide
        $s6 = "{\"Type\":\"TestURLDump\",\"SessionID\":\"" wide
        $s7 = "<ReceiveParticipantList>" ascii
        $s8 = "<potocSkr>" ascii
        $s9 = "fuck_sd" fullword ascii
        $s10 = "HandleBotKiller" fullword ascii
        $s11 = "RunBotKiller" fullword ascii
        $s12 = "ConnectToServer" fullword ascii
        $s13 = "KillBrowsers" fullword ascii
        $s14 = "keybd_event" fullword ascii
        $s15 = "FuckCodeImg" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
