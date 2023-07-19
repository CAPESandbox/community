rule Snake_Keylogger {
    meta:
        author = "ditekSHen"
        description = "Detects Snake Keylogger"
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
        // Snake Keylogger Stub New
        $x1 = "$%SMTPDV$" wide
        $x2 = "$#TheHashHere%&" wide
        $x3 = "%FTPDV$" wide
        $x4 = "$%TelegramDv$" wide
        $x5 = "KeyLoggerEventArgs" ascii
        $m1 = "| Snake Keylogger" ascii wide
        $m2 = /(Screenshot|Clipboard|keystroke) Logs ID/ ascii wide
        $m3 = "SnakePW" ascii wide
        $m4 = "\\SnakeKeylogger\\" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (all of ($id*) or 6 of ($s*) or (1 of ($id*) and 3 of ($s*)) or 4 of ($x*))) or (2 of ($m*))
}

rule SNAKE {
    meta:
        author = "ditekSHen"
        description = "Detects SNAKE implant"
        cape_type = "SNAKE Payload"
    strings:
        $c1 = { 25 73 23 31 }
        $c2 = { 25 73 23 32 }
        $c3 = { 25 73 23 33 }
        $c4 = { 25 73 23 34 }
        $c5 = { 2e 74 6d 70 }
        $c6 = { 2e 73 61 76 }
        $c7 = { 2e 75 70 64 }
        $s1 = "tapisetschema.dll" fullword wide
        $s2 = "\\\\.\\%s\\\\" fullword ascii wide
        $s3 = "\\BaseNamedObjects\\%S" fullword wide
        $s4 = "{CACE3174-CF88-4906-921A-A16A7DC8CF4B}.{B6066E99-37D7-4668-9B06-301CE2C1D367}.crmlog" ascii
        $s5 = "-crash-" fullword ascii
        $s6 = "rcv_buf=%d%c" fullword ascii
        $s7 = "write_peer_nfo=%s:%d%cfrag_no_scrambling=Y%c" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and (all of ($s*) or (all of ($c*) and 1 of ($s*)))) or (all of ($c*) and 1 of ($s*))
}
