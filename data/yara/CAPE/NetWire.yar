rule NetWire
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net> & David Cannings"
		ref = "http://malwareconfig.com/stats/NetWire"
		maltype = "Remote Access Trojan"
		filetype = "exe"
        cape_type = "NetWire Payload"
		
    strings:

        $exe1 = "%.2d-%.2d-%.4d"
        $exe2 = "%s%.2d-%.2d-%.4d"
        $exe3 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
        $exe4 = "wcnwClass"
        $exe5 = "[Ctrl+%c]"
        $exe6 = "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
        $exe7 = "%s\\.purple\\accounts.xml"

        $s1 = "-w %d >nul 2>&1" ascii
        $s2 = "[Log Started]" ascii
        $s3 = "DEL /s \"%s\" >nul 2>&1" fullword ascii
        $s4 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b" fullword ascii
        $s5 = ":deleteSelf" ascii
        $s6 = "%s\\%s.bat" fullword ascii

    condition:
        all of ($exe*) or all of ($s*)
}
