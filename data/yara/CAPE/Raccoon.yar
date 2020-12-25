rule Raccoon {
    meta:
        author = "ditekSHen"
        description = "Detects Raccoon/Racealer infostealer"
        cape_type = "Raccoon payload"
    strings:
        $s1 = "endptr == token_buffer.data() + token_buffer.size()" fullword wide
        $s2 = "inetcomm server passwords" fullword wide
        $s3 = "\\json.hpp" wide
        $s4 = "CredEnumerateW" fullword ascii
        $s5 = "Microsoft_WinInet_" fullword wide
        $s6 = "already connected" fullword ascii
        $s7 = "copy_file" fullword ascii
        $s8 = "\"; filename=\"" fullword ascii
        $s9 = "%[^:]://%[^/]%[^" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 8 of them
}
