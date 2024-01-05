rule LummaStealer {
    meta:
        author = "ditekSHen"
        description = "Detects Lumma Stealer"
        cape_type = "LummaStealer Payload"
    strings:
        $x1 = /Lum[0-9]{3}xedmaC2,\sBuild/ ascii
        $x2 = /LID\(Lu[0-9]{3}xedmma\sID\):/ ascii
        $s1 = /os_c[0-9]{3}xedrypt\.encry[0-9]{3}xedpted_key/ fullword ascii
        $s2 = "c2sock" wide
        $s3 = "c2conf" wide
        $s4 = "TeslaBrowser/" wide
        $s5 = "Software.txt" fullword wide
        $s6 = "SysmonDrv" fullword
        $s7 = "*.eml" fullword wide nocase
        $s8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $s9 = "- Screen Resoluton:" ascii
        $s10 = "lid=%s" ascii
        $s11 = "&ver=" ascii
        $s12 = "769cb9aa22f4ccc412f9cbc81feedd" fullword wide
        $s13 = "gapi-node.io" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (1 of ($x*) and 2 of ($s*)) or 5 of ($s*) or 7 of them)
}
