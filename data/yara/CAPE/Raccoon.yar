rule Raccoon {
    meta:
        author = "ditekSHen"
        description = "Raccoon stealer payload"
        cape_type = "Raccoon Infostealer Payload"
    strings:
        $s1 = "inetcomm server passwords" fullword wide
        $s2 = "content-disposition: form-data; name=\"file\"; filename=\"data.zip\"" fullword ascii
        $s3 = ".?AVfilesystem_error@v1@filesystem@experimental@std@@" fullword ascii
        $s4 = "CredEnumerateW" fullword ascii
        $s5 = "%[^:]://%[^/]%[^" fullword ascii
        $s6 = "%99[^:]://%99[^/]%99[^" fullword ascii
        $s7 = "Login Data" wide
        $s8 = "m_it.object_iterator != m_object->m_value.object->end()" fullword wide
        $x1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $x2 = "\\json.hpp" wide
        $x3 = "Microsoft_WinInet_" fullword wide
        $x4 = "Microsoft_WinInet_*" fullword wide
    condition:
        uint16(0) == 0x5a4d and ((3 of ($x*) and 2 of ($s*)) or (4 of ($s*) and 1 of ($x*)))
}
