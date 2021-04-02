rule Snatch {
    meta:
        author = "ditekSHen"
        description = "Detects Snatch / GoRansome / MauriGo ransomware"
        cape_type = "Snatch Ransomware Payload"
    strings:
        $s1 = "main.encryptFile" ascii
        $s2 = "main.encryptFileExt" ascii
        $s3 = "main.deleteShadowCopy" ascii
        $s4 = "main.Shadow" fullword ascii
        $s5 = "main.RecoverMe" fullword ascii
        $s6 = "main.encodedCommandsList" ascii
        $s7 = "github.com/mauri870/ransomware" ascii
        $m1 = "Dear You, ALl Your files On YOUR network computers are encrypted" ascii
        $m2 = "You have to pay the ransom of %s USD in bitcoins to the address" ascii
        $m3 = "REMEMBER YOU FILES ARE IN SAVE HANDS AND WILL BE RESTORED OR RECOVERED ONCE PAYMENT IS DONE" ascii
        $m4 = ":HELP FEEED A CHILD:" ascii
        $m5 = ">SYSTEM NETWORK ENCRYPTED<" ascii
        $m6 = "YOUR IDENTIFICATION : %s"
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or 2 of ($m*) or (1 of ($m*) and 1 of ($s*)))
}
