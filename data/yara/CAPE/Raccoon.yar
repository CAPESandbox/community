rule Raccoon {
    meta:
        author = "ditekSHen"
        description = "Raccoon stealer payload"
        cape_type = "Raccoon Payload"
    strings:
        $s1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s2 = "inetcomm server passwords" fullword wide
        $s3 = "content-disposition: form-data; name=\"file\"; filename=\"data.zip\"" fullword ascii
        $s4 = "\\json.hpp" wide
        $s5 = ".?AVfilesystem_error@v1@filesystem@experimental@std@@" fullword ascii
        $s6 = "CredEnumerateW" fullword ascii
        $s7 = "Microsoft_WinInet_" fullword wide
        $r1 = "%[^:]://%[^/]%[^" fullword ascii
        $r2 = "%99[^:]://%99[^/]%99[^" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($s*) or (5 of ($s*) and 1 of ($r*)))
}
