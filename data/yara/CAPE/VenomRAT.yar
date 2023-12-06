rule VenomRAT {
    meta:
        author = "ditekSHen"
        description = "Detects VenomRAT"
        cape_type = "VenomRAT Payload"
    strings:
       $x1 = "Venom RAT + HVNC" fullword ascii
       $x2 = "Venom" fullword ascii
       $x3 = "VenomByVenom" fullword wide
       $s1 = "/c schtasks /create /f /sc onlogon /rl highest /tn \"" fullword wide
       $s2 = "UmVjZWl2ZWQ" wide
       $s3 = "Pac_ket" fullword wide
       $s4 = "Po_ng" fullword wide
    condition:
       uint16(0) == 0x5a4d and (1 of ($x*) and 2 of ($s*))
}
