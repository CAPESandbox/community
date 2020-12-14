import "pe"

rule RedLineDropperAHK {
    meta:
        author = "ditekshen"
        description = "RedLine infostealer payload"
        cape_type = "RedLine Payload"
    strings:
        $s1 = ".SetRequestHeader(\"User-Agent\",\" ( \" OSName \" | \" bit \" | \" CPUNAme \"\"" ascii
        $s2 = ":= \" | Windows Defender\"" ascii
        $s3 = "WindowSpy.ahk" wide
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule RedLineDropperEXE {
    meta:
      author = "ditekSHen"
      description = "Detects executables dropping RedLine infostealer"
      cape_type = "RedLineDropperEXE Payload"
    strings:
        $s1 = "Wizutezinod togeto0Rowadufevomuki futenujilazem jic lefogatenezinor" fullword wide
        $s2 = "dapotevasowefopesin" fullword wide
        $s3 = "6Tatafamobevofaj bizafoju peyovavacoco lizine kezakajuj" fullword wide
        $s4 = "Civokabitohi zigayag" fullword wide
        $s5 = "Lawuherusozeru kucu zam0Zorizeyuk lepaposupu gala kinarusot ruvasaxehuwo" fullword wide
        $s6 = "ClearEventLogW" fullword ascii
    condition:
        uint16(0) == 0x5a4d and pe.exports("_fgeek@8") and 2 of them
}
