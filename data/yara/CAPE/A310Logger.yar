rule A310Logger {
    meta:
        author = "ditekSHen"
        description = "Detects A310Logger"
        cape_type = "A310Logger Payload"
    strings:
        $p1 = "C:\\Users\\e-techz\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" wide
        $p2 = "Users\\e-techz\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\" wide
        $s1 = "@ENTIFIER=" wide
        $s2 = "@echz\\App" fullword wide
        $s3 = "ExecQuery" fullword wide
        $s4 = "MSXML2.ServerXMLHTTP.6.0" fullword wide
        $s5 = "Content-Disposition: form-data; name=\"document\"; filename=\"" wide
        $s6 = "CopyHere" fullword wide
        $s7 = "] Error in" fullword wide
        $s8 = "shell.application" fullword wide
        $s9 = "SetRequestHeader" fullword wide
        $s10 = "\\Ethereum\\keystore" fullword wide
        $en1 = "Unsupported encryption" fullword wide
        $en2 = "BCryptOpenAlgorithmProvider(SHA1)" fullword wide
        $en3 = "BCryptGetProperty(ObjectLength)" fullword wide
        $en4 = "BCryptGetProperty(HashDigestLength)" fullword wide
    condition:
        uint16(0) == 0x5a4d and (7 of ($s*) or (1 of ($p*) and 3 of ($s*)) or (all of ($en*) and 4 of ($s*)))
}
