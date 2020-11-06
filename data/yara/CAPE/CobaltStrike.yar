rule CobaltStrike {
    meta:
        author = "ditekshen"
        description = "CobaltStrike payload"
        cape_type = "CobaltStrike Payload"
    strings:
        $s1 = "%%IMPORT%%" fullword ascii
        $s2 = "www6.%x%x.%s" fullword ascii
        $s3 = "cdn.%x%x.%s" fullword ascii
        $s4 = "api.%x%x.%s" fullword ascii
        $s5 = "%s (admin)" fullword ascii
        $s6 = "could not spawn %s: %d" fullword ascii
        $s7 = "Could not kill %d: %d" fullword ascii
        $s8 = "Could not connect to pipe (%s): %d" fullword ascii
        $s9 = /%s\.\d[(%08x).]+\.%x%x\.%s/ ascii

        $pwsh1 = "IEX (New-Object Net.Webclient).DownloadString('http" ascii
        $pwsh2 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($pwsh*) and 2 of ($s*)) or (#s9 > 6 and 4 of them)) 
}
