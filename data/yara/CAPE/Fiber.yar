rule Fiber {
    meta:
        author = "ditekSHen"
        description = "Detects Fiber .NET injector"
        cape_type = "Fiber Payload"
    strings:
        $x1 = "Fiber.dll" fullword ascii
        $s1 = "-WindowStyle Hidden Copy-Item -Path *.vbs -Destination" wide
        $s2 = "-WindowStyle Hidden {0} -WindowStyle Hidden Start-Sleep 5; Start-Process {1}" wide
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s4 = "WScript.Shell" fullword wide
        $s5 = "{0}_{1:N}.lnk" fullword wide
        $s6 = "notepad.exe,0" fullword wide
        $i1 = "AppLaunch.exe" fullword wide
        $i2 = "aspnet_regbrowsers.exe" fullword wide
        $i3 = "cvtres.exe" fullword wide
        $i4 = "ilasm.exe" fullword wide
        $i5 = "jsc.exe" fullword wide
        $i6 = "MSBuild.exe" fullword wide
        $i7 = "RegAsm.exe" fullword wide
        $i8 = "RegSvcs.exe" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((1 of ($x*) and 3 of ($s*) and 2 of ($i*)) or (4 of ($s*) and 4 of ($i*)) or (2 of ($s*) and 6 of ($i*)))
}
