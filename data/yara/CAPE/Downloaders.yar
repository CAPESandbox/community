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
