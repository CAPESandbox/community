rule Meterpreter {
    meta:
        author = "ditekSHen"
        description = "Detects Meterpreter payload"
        cape_type = "Meterpreter"
    strings:
        $s1 = "PACKET TRANSMIT" fullword ascii
        $s2 = "PACKET RECEIVE" fullword ascii
        $s3 = "\\\\%s\\pipe\\%s" fullword ascii wide
        $s4 = "%04x-%04x:%s" fullword wide
        $s5 = "server.dll" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and all of them) or (filesize < 300KB and all of them)
}
