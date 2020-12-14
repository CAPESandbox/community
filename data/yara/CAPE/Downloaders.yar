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
      description = "Detects downloader agent"
      cape_type = "DLAgent02 Downloader Payload"
    strings:
        $s1 = "/c timeout {0}" fullword wide
        $s2 = "^(https?|ftp):\\/\\/" fullword wide
        $s3 = "HttpWebRequest" fullword ascii
        $s4 = "GetResponseStream" fullword ascii
        $s5 = "set_FileName" fullword ascii
        $s6 = "set_UseShellExecute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 250KB and all of them
}
