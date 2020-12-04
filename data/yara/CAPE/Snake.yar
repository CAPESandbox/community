rule Snake {
    meta:
        author = "ditekSHen"
        description = "Snake keylogger payload"
        cape_type = "Snake Payload"
    strings:
        $id1 = "SNAKE-KEYLOGGER" fullword ascii
        $id2 = "----------------S--------N--------A--------K--------E----------------" ascii
        $s1 = "_KPPlogS" fullword ascii
        $s2 = "_Scrlogtimerrr" fullword ascii
        $s3 = "_Clpreptimerr" fullword ascii
        $s4 = "_clprEPs" fullword ascii
        $s5 = "_kLLTIm" fullword ascii
        $s6 = "_TPSSends" fullword ascii
        $s7 = "_ProHfutimer" fullword ascii
        $s8 = "GrabbedClp" fullword ascii
        $s9 = "StartKeylogger" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($id*) or 6 of ($s*) or (1 of ($id*) and 3 of ($s*)))
}
