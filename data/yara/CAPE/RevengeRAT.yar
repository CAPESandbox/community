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

        $s1 = "GetCamera" fullword ascii
        $s2 = "GetAV" fullword ascii
        $s3 = "keepAlivePing!" fullword ascii
        $s4 = "Revenge-RAT" fullword ascii
        $s5 = "*-]NK[-*" fullword ascii
        $s6 = "RV_MUTEX" fullword ascii
        $s7 = "set_SendBufferSize" fullword ascii

        $q1 = "Select * from AntiVirusProduct" fullword ascii
        $q2 = "SELECT * FROM FirewallProduct" fullword ascii
        $q3 = "select * from Win32_Processor" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($l*) and 3 of ($s*)) or (all of ($q*) and 3 of ($s*)))
}
