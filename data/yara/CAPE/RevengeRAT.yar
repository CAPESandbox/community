rule RevengeRAT {
    meta:
        author = "ditekshen"
        description = "RevengeRAT and variants payload"
        cape_type = "RevengeRAT payload"
    strings:
        $l1 = "Lime.Connection" fullword ascii
        $l2 = "Lime.Packets" fullword ascii
        $l3 = "Lime.Settings" fullword ascii
        $l4 = "Lime.NativeMethods" fullword ascii

        $s1 = "GetAV" fullword ascii
        $s2 = "keepAlivePing!" fullword ascii wide
        $s3 = "Revenge-RAT" fullword ascii wide
        $s4 = "*-]NK[-*" fullword ascii wide
        $s5 = "RV_MUTEX" fullword ascii wide
        $s6 = "set_SendBufferSize" fullword ascii

        $q1 = "Select * from AntiVirusProduct" fullword ascii wide
        $q2 = "SELECT * FROM FirewallProduct" fullword ascii wide
        $q3 = "select * from Win32_Processor" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($l*) and 3 of ($s*)) or (all of ($q*) and 3 of ($s*)))
}
