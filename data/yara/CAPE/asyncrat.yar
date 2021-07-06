rule asyncrat {
    meta:
        author      = "c3rb3ru5"
        author      = "JPCERT/CC Incident Response Group"
        description = "ASyncRAT"
        reference   = "https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat"
        hash        = "330493a1ba3c3903040c9542e6348fab"
        type        = "malware.rat"
        created     = "2021-05-29"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $magic_cslr_0 = "BSJB"
        $salt         = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43
                         00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
        $b1           = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00
                         00}
        $b2           = {09 50 00 6F 00 6E 00 67 00 00}
        $s1           = "pastebin" ascii wide nocase
        $s2           = "pong" wide
        $s3           = "Stub.exe" ascii wide
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        filesize < 2605056 and
        $magic_cslr_0 and
        ($salt and
         (2 of ($s*) or
         1 of ($b*))) or
        (all of ($b*) and
         2 of ($s*))
}
