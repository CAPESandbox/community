rule KoadicJS {
    meta:
        author = "ditekshen"
        description = "Koadic post-exploitation framework JS payload"
        cape_type = "KoadicJS payload"
    strings:
        $s1 = "window.moveTo(-1337, -2019);" fullword ascii
        $s2 = "window.onerror = function(sMsg, sUrl, sLine) { return false; }" fullword ascii
        $s3 = "window.onfocus = function() { window.blur(); }" fullword ascii
        $s4 = "window.resizeTo(2, 4);" fullword ascii
        $s5 = "window.blur();" fullword ascii
        $s6 = "scroll=\"no\" navigable=\"no\" />" fullword ascii
        $s7 = "<hta:application caption=\"no\" windowState=\"minimize\" showInTaskBar=\"no\"" fullword ascii
    condition:
        all of them
}
