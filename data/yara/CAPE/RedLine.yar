rule RedLine {
    meta:
        author = "ditekshen"
        description = "RedLine infostealer payload"
        cape_type = "RedLine Payload"
    strings:
        $s1 = ".SetRequestHeader(\"User-Agent\",\" ( \" OSName \" | \" bit \" | \" CPUNAme \"\"" ascii
        $s2 = ":= \" | Windows Defender\"" ascii
        $s3 = "WindowSpy.ahk" wide
    condition:
        uint16(0) == 0x5a4d and all of them
}
