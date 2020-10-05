rule IRCBot {
    meta:
      author = "ditekshen"
      description = "IRCBot payload"
      cape_type = "IRCBot payload"
    strings:
        $s1 = ".okuninstall" fullword wide
        $s2 = ".oksnapshot" fullword wide
        $s3 = "\\uspread.vbs" fullword wide
        $s4 = "KEYLogger" ascii nocase
        $s5 = "GetKeyLogs" fullword ascii
        $s6 = "GetLoocationInfo" fullword ascii
        $s7 = "CaputerScreenshot" fullword ascii
        $s8 = "get_SCRIPT_DATA" fullword ascii
        $s9 = /irc_(server|nickname|password|channle)/ fullword ascii
        $s10 = "machine_screenshot" fullword ascii
        $s11 = "CollectPassword" fullword ascii
        $s12 = "USBInfection" fullword ascii nocase

        $cnc1 = "&command=UpdateAndGetTasks&machine_id=" wide
        $cnc2 = "&machine_os=1&privateip=" wide
        $cnc3 = "&command=InsertTaskExecution&excuter_id=" wide
        $cnc4 = "&command=RegisterNewMachine" wide
        $cnc5 = "&command=UpdateNewMachine" wide
        $cnc6 = "&command=GetPayloads&keys=" wide
        $cnc7 = "&command=SaveSnapshot" wide

        $pdb = "\\Projects\\USBStarter\\USBStarter\\obj\\Release\\USBStarter.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or 3 of ($cnc*) or ($pdb and 2 of them))
}
