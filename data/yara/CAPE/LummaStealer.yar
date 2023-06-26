rule LummaStealer {
    meta:
        author = "ditekSHen"
        description = "Detects Lumma Stealer"
        cape_type = "LummaStealer Payload"
    strings:
        $x1 = /Lum[0-9]{3}xedmaC2,\sBuild/ ascii
        $x2 = /LID\(Lu[0-9]{3}xedmma\sID\):/ ascii
        $s1 = /os_c[0-9]{3}xedrypt\.encry[0-9]{3}xedpted_key/ fullword ascii
        $s2 = "profile.info_cache" fullword ascii
        $s3 = "lid=%s&ver=" ascii
        $s4 = "c2sock" wide
        $s5 = "c2conf" wide
        $s6 = "TeslaBrowser/" wide
        $s7 = "2%localappdata%\\Packages" fullword wide
        $s8 = "Software.txt" fullword wide
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (1 of ($x*) and 2 of ($s*)) or 5 of ($s*) or 7 of them)
}
