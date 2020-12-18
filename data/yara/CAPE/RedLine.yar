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
        $s2 = "6Tatafamobevofaj bizafoju peyovavacoco lizine kezakajuj" fullword wide
        $s3 = "Lawuherusozeru kucu zam0Zorizeyuk lepaposupu gala kinarusot ruvasaxehuwo" fullword wide
        $s4 = "ClearEventLogW" fullword ascii
        $s5 = "ProductionVersion" fullword wide
        $s6 = "Vasuko)Yugenizugilobo toxocivoriye yexozoyohuzeb" wide
        $s7 = "Yikezevavuzus gucajanesan#Rolapucededoxu xewulep fuwehofiwifi" wide
    condition:
        uint16(0) == 0x5a4d and (pe.exports("_fgeek@8") and 2 of them) or 
        (
            2 of them and 
            for any i in (0 .. pe.number_of_sections) : (
                (
                    pe.sections[i].name == ".rig"
                )
            )
        )
}

rule RedLine {
    meta:
        author = "ditekshen"
        description = "Detects RedLine infostealer"
        cape_type = "RedLine Payload"
    strings:
        $s1 = { 23 00 2b 00 33 00 3b 00 43 00 53 00 63 00 73 00 }
        $s2 = { 68 10 84 2d 2c 71 ea 7e 2c 71 ea 7e 2c 71 ea 7e
                32 23 7f 7e 3f 71 ea 7e 0b b7 91 7e 2b 71 ea 7e
                2c 71 eb 7e 5c 71 ea 7e 32 23 6e 7e 1c 71 ea 7e
                32 23 69 7e a2 71 ea 7e 32 23 7b 7e 2d 71 ea 7e }
        $s3 = { 83 ec 38 53 b0 ?? 88 44 24 2b 88 44 24 2f b0 ??
                88 44 24 30 88 44 24 31 88 44 24 33 55 56 8b f1
                b8 0c 00 fe ff 2b c6 89 44 24 14 b8 0d 00 fe ff
                2b c6 89 44 24 1c b8 02 00 fe ff 2b c6 89 44 24
                18 b3 32 b8 0e 00 fe ff 2b c6 88 5c 24 32 88 5c
                24 41 89 44 24 28 57 b1 ?? bb 0b 00 fe ff b8 03
                00 fe ff 2b de 2b c6 bf 00 00 fe ff b2 ?? 2b fe
                88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34
                78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6
                44 24 41 33 c6 44 24 43 ?? c6 44 24 44 74 88 54
                24 46 c6 44 24 40 ?? c6 44 24 39 62 c7 44 24 10 }
        $s4 = "B|BxBtBpBlBhBdB`B\\BXBTBPBLBHBDB@B<B8B4B0B,B(B$B B" fullword wide
        $s5 = " delete[]" fullword ascii
        $s6 = "constructor or from DllMain." ascii

        $x1 = "RedLine.Reburn" ascii
        $x2 = "RedLine.Client." ascii
        $x3 = "hostIRemotePanel, CommandLine: " fullword wide
        $u1 = "<ParseCoinomi>" ascii
        $u2 = "<ParseBrowsers>" ascii
        $u3 = "<GrabScreenshot>" ascii
        $u4 = "UserLogT" fullword ascii
        $u5 = "FingerPrintT" fullword ascii
        $u6 = "InstalledBrowserInfoT" fullword ascii
        $u7 = "RunPE" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and (all of ($s*) or 2 of ($x*) or all of ($u*) or (1 of ($x*) and 5 of ($u*)))) or (all of ($x*) and 4 of ($s*))
}
