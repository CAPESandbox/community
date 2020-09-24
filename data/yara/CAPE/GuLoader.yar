rule GuLoader {
    meta:
        author = "ditekshen"
        description = "Shellcode injector and downloader"
        cape_type = "Shellcode injector"
    strings:
        $s1 = "wininet.dll" fullword ascii
        $s2 = "ShellExecuteW" fullword ascii
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" fullword ascii
        $s5 = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" fullword ascii
        $s6 = "Startup key" fullword ascii
        $s7 = "\\qemu-ga\\qga.state" ascii nocase
        $s8 = "\\qga\\qga.exe" ascii nocase
        $s9 = "\\Qemu-ga\\qemu-ga.exe" ascii nocase
        $s10 = "WScript.Shell" ascii

        $l1 = "shell32" fullword ascii
        $l2 = "kernel32" fullword ascii
        $l3 = "advapi32" fullword ascii
        $l4 = "user32" fullword ascii

        $o1 = "msvbvm60.dll" fullword wide
        $o2 = "\\syswow64\\" fullword wide
        $o3 = "\\system32\\" fullword wide
        $o4 = "\\Microsoft.NET\\Framework\\" fullword wide
        $o5 = "USERPROFILE=" fullword wide
        $o6 = "windir=" fullword wide
        $o7 = "APPDATA=" fullword wide
        $o8 = "RegAsm.exe" fullword wide
        $o9 = "ProgramFiles=" fullword wide
        $o10 = "TEMP=" fullword wide

        $url1 = "https://drive.google.com/uc?export=download&id=" ascii
        $url2 = "https://onedrive.live.com/download?cid=" ascii
        $url3 = "http://myurl/myfile.bin" fullword ascii
        $url4 = "http" ascii // fallback
    condition:
        (4 of ($s*) and 3 of ($l*) and 3 of ($o*) and 1 of ($url*)) or (5 of ($s*) and 3 of ($l*) and 3 of ($o*))
}
