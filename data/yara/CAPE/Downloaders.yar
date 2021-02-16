rule DLAgent01 {
    meta:
      author = "ditekshen"
      description = "Detects downloader agent"
      cape_type = "DLAgent01 Downloader Payload"
    strings:
        $s1 = "Mozilla/5.0 Gecko/41.0 Firefox/41.0" fullword wide
        $s2 = "/Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List" fullword wide
        $s3 = "GUID.log" fullword wide
        $s4 = "NO AV" fullword wide
        $s5 = "%d:%I64d:%I64d:%I64d" fullword wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule DLAgent02 {
    meta:
      author = "ditekSHen"
      description = "Detects known downloader agent downloading encoded binaries in patches from paste-like websites, most notably hastebin"
      cape_type = "DLAgent02 Downloader Payload"
    strings:
        $x1 = "/c timeout {0}" fullword wide
        $x2 = "^(https?|ftp):\\/\\/" fullword wide
        $x3 = "{0}{1}{2}{3}" wide
        $x4 = "timeout {0}" fullword wide
        $s1 = "HttpWebRequest" fullword ascii
        $s2 = "GetResponseStream" fullword ascii
        $s3 = "set_FileName" fullword ascii
        $s4 = "set_UseShellExecute" fullword ascii
        $s5 = "WebClient" fullword ascii
        $s6 = "set_CreateNoWindow" fullword ascii
        $s7 = "DownloadString" fullword ascii
        $s8 = "WriteByte" fullword ascii
        $s9 = "CreateUrlCacheEntryW" fullword ascii
        $s10 = "HttpStatusCode" fullword ascii
        $s11 = "FILETIME" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and ((2 of ($x*) and 2 of ($s*)) or (#x3 > 2 and 4 of ($s*)))
}

rule DLAgent03 {
    meta:
      author = "ditekSHen"
      description = "Detects known Delphi downloader agent downloading second stage payload, notably from discord"
      cape_type = "DLAgent03 Downloader Payload"
    strings:
        $delph1 = "FastMM Borland Edition" fullword ascii
        $delph2 = "SOFTWARE\\Borland\\Delphi" ascii
        $v1_1 = "InternetOpenUrlA" fullword ascii
        $v1_2 = "CreateFileA" fullword ascii
        $v1_3 = "WriteFile" fullword ascii
        $v1_4 = "$(,048<@DHLLPPTTXX\\\\``ddhhllppttttxxxx||||" ascii
        $v2_1 = "WinHttp.WinHttpRequest.5.1" fullword ascii
        $v2_2 = { 6f 70 65 6e ?? ?? ?? ?? ?? 73 65 6e 64 ?? ?? ?? ?? 72 65 73 70 6f 6e 73 65 74 65 78 74 }
        // $pat is slowing down scanning
        //$pat = /[a-f0-9]{168}/ fullword ascii
        $url1 = "https://discord.com/" fullword ascii
        $url2 = "http://www.superutils.com" fullword ascii
    condition:
        //uint16(0) == 0x5a4d and 1 of ($delph*) and $discord and ((all of ($v1*) or all of ($v2*)) or $pat)
        uint16(0) == 0x5a4d and 1 of ($delph*) and 1 of ($url*) and (all of ($v1*) or 1 of ($v2*))
}

rule DLAgent04 {
    meta:
      author = "ditekSHen"
      description = "Detects known downloader agent downloading encoded binaries in patches from paste-like websites, most notably hastebin"
      cape_type = "DLAgent04 Downloader Payload"
    strings:
        $x1 = "@@@http" ascii wide
        $s1 = "HttpWebRequest" fullword ascii
        $s2 = "GetResponseStream" fullword ascii
        $s3 = "set_FileName" fullword ascii
        $s4 = "set_UseShellExecute" fullword ascii
        $s5 = "WebClient" fullword ascii
        $s6 = "set_CreateNoWindow" fullword ascii
        $s7 = "DownloadString" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and #x1 > 1 and 4 of ($s*)
}

rule DLAgent05 {
    meta:
        author = "ditekSHen"
        description = "Detects an unknown dropper. Typically exisys as a DLL in base64-encoded gzip-compressed file embedded within another executable"
        cape_type = "DLAgent05 Downloader Payload"
    strings:
        $s1 = "MARCUS.dll" fullword ascii wide
        $s2 = "GZipStream" fullword ascii
        $s3 = "MemoryStream" fullword ascii
        $s4 = "proj_name" fullword ascii
        $s5 = "res_name" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule DLAgent06 {
    meta:
      author = "ditekSHen"
      description = "Detects known downloader agent downloading encoded binaries in patches"
      cape_type = "DLAgent06 Downloader Payload"
    strings:
        $s1 = "totallist" fullword ascii wide
        $s2 = "LINKS_HERE" fullword wide
        $s3 = "Load" fullword wide
        $s4 = "EntryPoint" fullword wide
        $s5 = "Invoke" fullword wide
        $s6 = "[SPLITTER]" fullword wide
        $var2_1 = "DownloadWeb" fullword ascii
        $var2_2 = "WriteByte" fullword ascii
        $var2_3 = "bigstring" fullword ascii
        $var2_4 = "MemoryStream" fullword ascii
        $var2_5 = "DownloadString" fullword ascii
        $var2_6 = "WebClient" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of ($s*) or (5 of ($var2*) and 3 of ($s*))
}

rule DLAgent07 {
    meta:
        author = "ditekSHen"
        description = "Detects delf downloader agent"
        cape_type = "DLAgent07 Downloader Payload"
    strings:
        $s1 = "C:\\Users\\Public\\Libraries\\temp" fullword ascii
        $s2 = "SOFTWARE\\Borland\\Delphi" ascii
        $o1 = { f3 a5 e9 6b ff ff ff 5a 5d 5f 5e 5b c3 a3 00 40 }
        $o2 = { e8 83 d5 ff ff 8b 15 34 40 41 00 89 10 89 58 04 }
        $o3 = { c3 8b c0 53 51 e8 f1 ff ff ff 8b d8 85 db 74 3e }
        $o4 = { e8 5c e2 ff ff 8b c3 e8 b9 ff ff ff 89 04 24 83 }
        $o5 = { 85 c0 74 1f e8 62 ff ff ff a3 98 40 41 00 e8 98 }
        $o6 = { 85 c0 74 19 e8 be ff ff ff 83 3d 98 40 41 00 ff }
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) and 5 of ($o*))
}
