rule INDICATOR_EXPLOIT_RTF_CVE_2017_0199_1 {
    meta:
        description = "Detects RTF documents potentially exploiting CVE-2017-0199"
        author = "ditekSHen"
    strings:
        // URL Moniker
        $urlmoniker1 = "e0c9ea79f9bace118c8200aa004ba90b" ascii nocase
        $urlmoniker2 = { 45 30 43 39 45 41 37 39 46 39 42 41 43 45 31 31
                         38 43 38 32 30 30 41 41 30 30 34 42 41 39 30 42 } // HEX + lower-case
        $urlmoniker3 = { 45 0a 30 0a 43 0a 39 0a 45 0a 41 0a 37 0a 39 0a 
                         46 0a 39 0a 42 0a 41 0a 43 0a 45 0a 31 0a 31 0a 
                         38 0a 43 0a 38 0a 32 0a 30 0a 30 0a 41 0a 41 0a 
                         30 0a 30 0a 34 0a 42 0a 41 0a 39 0a 30 0a 42 }    // HEX + lower-case + \x0a manipulation
        $urlmoniker4 = { 45 0d 0a 30 0d 0a 43 0d 0a 39 0d 0a 45 0d 0a 41
                         0d 0a 37 0d 0a 39 0d 0a 46 0d 0a 39 0d 0a 42 0d 
                         0a 41 0d 0a 43 0d 0a 45 0d 0a 31 0d 0a 31 0d 0a
                         38 0d 0a 43 0d 0a 38 0d 0a 32 0d 0a 30 0d 0a 30
                         0d 0a 41 0d 0a 41 0d 0a 30 0d 0a 30 0d 0a 34 0d
                         0a 42 0d 0a 41 0d 0a 39 0d 0a 30 0d 0a 42 }       // HEX + lower-case + \x0d0a manipulation
        $urlmoniker5 = { 65 30 63 39 65 61 37 39 66 39 62 61 63 65 31 31
                         38 63 38 32 30 30 61 61 30 30 34 62 61 39 30 62 } // HEX + upper-case
        $urlmoniker6 = { 65 0a 30 0a 63 0a 39 0a 65 0a 61 0a 37 0a 39 0a
                         66 0a 39 0a 62 0a 61 0a 63 0a 65 0a 31 0a 31 0a
                         38 0a 63 0a 38 0a 32 0a 30 0a 30 0a 61 0a 61 0a
                         30 0a 30 0a 34 0a 62 0a 61 0a 39 0a 30 0a 62 }    // HEX + upper-case + \x0a manipulation
        $urlmoniker7 = { 65 0d 0a 30 0d 0a 63 0d 0a 39 0d 0a 65 0d 0a 61
                         0d 0a 37 0d 0a 39 0d 0a 66 0d 0a 39 0d 0a 62 0d
                         0a 61 0d 0a 63 0d 0a 65 0d 0a 31 0d 0a 31 0d 0a
                         38 0d 0a 63 0d 0a 38 0d 0a 32 0d 0a 30 0d 0a 30
                         0d 0a 61 0d 0a 61 0d 0a 30 0d 0a 30 0d 0a 34 0d
                         0a 62 0d 0a 61 0d 0a 39 0d 0a 30 0d 0a 62 }       // HEX + upper-case + \x0d0a manipulation 
        /* is slowing down scanning
        $urlmoniker2 = { 45 [0-2] 30 [0-2] 43 [0-2] 39 [0-2] 45 [0-2] 41 [0-2] 37 [0-2]
                         39 [0-2] 46 [0-2] 39 [0-2] 42 [0-2] 41 [0-2] 43 [0-2] 45 [0-2]
                         31 [0-2] 31 [0-2] 38 [0-2] 43 [0-2] 38 [0-2] 32 [0-2] 30 [0-2]
                         30 [0-2] 41 [0-2] 41 [0-2] 30 [0-2] 30 [0-2] 34 [0-2] 42 [0-2]
                         41 [0-2] 39 [0-2] 30 [0-2] 42 }
        $urlmoniker2 = { 45 [0-2] 30 [0-2] 43 [0-2] 39 [0-2] 45 [0-2] 41 [0-2] 37 [0-2]
                         39 [0-2] 46 [0-2] 39 [0-2] 42 [0-2] 41 [0-2] 43 [0-2] 45 [0-2]
                         31 [0-2] 31 [0-2] 38 [0-2] 43 [0-2] 38 [0-2] 32 [0-2] 30 [0-2]
                         30 [0-2] 41 [0-2] 41 [0-2] 30 [0-2] 30 [0-2] 34 [0-2] 42 [0-2]
                         41 [0-2] 39 [0-2] 30 [0-2] 42 }
        $urlmoniker3 = { 65 [0-2] 30 [0-2] 63 [0-2] 39 [0-2] 65 [0-2] 61 [0-2] 37 [0-2]
                         39 [0-2] 66 [0-2] 39 [0-2] 62 [0-2] 61 [0-2] 63 [0-2] 65 [0-2]
                         31 [0-2] 31 [0-2] 38 [0-2] 63 [0-2] 38 [0-2] 32 [0-2] 30 [0-2]
                         30 [0-2] 61 [0-2] 61 [0-2] 30 [0-2] 30 [0-2] 34 [0-2] 62 [0-2]
                         61 [0-2] 39 [0-2] 30 [0-2] 62 }
        */
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" ascii nocase // HEX manipulated
        $ole5 = { 64 0a 30 0a 63 0a 66 0a 31 0a 31 0a 65 0a 30 }
        $ole6 = { 64 0d 0a 30 0d 0a 63 0d 0a 66 0d 0a 31 0d 0a 31 0d 0a 65 0d 0a 30 }
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
        
    condition:
        uint32(0) == 0x74725c7b and 1 of ($urlmoniker*) and 1 of ($ole*) and 1 of ($obj*)
}

rule INDICATOR_EXPLOIT_RTF_CVE_2017_11882_1 {
    meta:
        description = "Detects RTF documents potentially exploiting CVE-2017-11882"
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $s1 = "02ce020000000000c000000000000046" ascii nocase
        // Root Entry
        $s2 = "52006f006f007400200045006e00740072007900" ascii nocase
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" // HEX manipulated
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
      uint32(0) == 0x74725c7b and all of ($s*) and 1 of ($ole*) and 2 of ($obj*)
}

rule INDICATOR_EXPLOIT_RTF_CVE_2017_11882_2 {
    meta:
        description = "detects an obfuscated RTF variant documents potentially exploiting CVE-2017-11882"
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq1 = "02ce020000000000c000000000000046" ascii nocase
        $eq2 = "equation." ascii nocase
        $eq3 = "6551754174496f4e2e33" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
        // Shellcode Artefacts
        $s1 = "4c6f61644c696272617279" ascii nocase                // LoadLibrary
        $s2 = "47657450726f6341646472657373" ascii nocase          // GetProcAddress
        $s3 = "55524c446f776e6c6f6164546f46696c65" ascii nocase    // URLDownloadToFile
        $s4 = "5368656c6c45786563757465" ascii nocase              // ShellExecute
        $s5 = "4578697450726f63657373" ascii nocase                // ExitProcess
    condition:
        uint32(0) == 0x74725c7b and 1 of ($eq*) and 1 of ($obj*) and 2 of ($s*)
}

rule INDICATOR_EXPLOIT_OLE_CVE_2017_11882_1 {
    meta:
        description = "detects OLE documents potentially exploiting CVE-2017-11882"
        author = "ditekSHen"
    strings:
        $s1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $s2 = { 02 ce 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        $s3 = "ole10native" wide nocase
        $s4 = "Root Entry" wide
    condition:
        uint16(0) == 0xcfd0 and all of them
}

rule INDICATOR_EXPLOIT_RTF_CVE_2017_8759_1 {
    meta:
        description = "detects CVE-2017-8759 weaponized RTF documents."
        author = "ditekSHen"
    strings:
        // 00000300-0000-0000-C000-000000000046: OLE2Link
        $clsid1 = { 00 03 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        $clsid2 = { 00 03 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
        $clsid3 = "0003000000000000c000000000000046" ascii nocase
        $clsid4 = "4f4c45324c696e6b" ascii nocase // HEX
        $clsid5 = "OLE2Link" ascii nocase
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" // HEX manipulated
        // Second Stage Artefacts
        $s1 = "wsdl=http" wide
        $s2 = "METAFILEPICT" ascii
        $s3 = "INCLUDEPICTURE \"http" ascii
        $s4 = "!This program cannot be run in DOS mode" ascii
    condition:
        uint32(0) == 0x74725c7b and 1 of ($clsid*) and 1 of ($ole*) and 2 of ($s*)
}

rule INDICATOR_EXPLOIT_RTF_CVE_2017_8759_2 {
    meta:
        description = "detects CVE-2017-8759 weaponized RTF documents."
        author = "ditekSHen"
    strings:
        // Msxml2.SAXXMLReader.
        // 88D96A0C-F192-11D4-A65F-0040963251E5: Msxml2.SAXXMLReader.6
        $clsid1 = { 88 d9 6a 0c f1 92 11 d4 a6 5f 00 40 96 32 51 e5 } 
        $clsid2 = "88d96a0cf19211d4a65f0040963251e5" ascii nocase
        $clsid3 = "4d73786d6c322e534158584d4c5265616465722e" ascii nocase // HEX
        $clsid4 = "Msxml2.SAXXMLReader." ascii nocase
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" // HEX manipulated
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
        $obj8 = "\\objclass htmlfile" ascii
        // SOAP Moniker
        $soap1 = "c7b0abec197fd211978e0000f8757e" ascii nocase
    condition:
        uint32(0) == 0x74725c7b and 1 of ($clsid*) and 1 of ($ole*) and (2 of ($obj*) or 1 of ($soap*))
}

rule INDICATOR_RTF_Embedded_Excel_SheetMacroEnabled {
    meta:
        description = "Detects RTF documents embedding an Excel sheet with macros enabled. Observed in exploit followed by dropper behavior"
        author = "ditekSHen"
    strings:
        // Embedded Excel
        $ex1 = "457863656c2e53686565744d6163726f456e61626c65642e" ascii nocase
        $ex2 = "0002083200000000c000000000000046" ascii nocase
        $ex3 = "Excel.SheetMacroEnabled."ascii
        // OLE Signature
        $ole1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $ole2 = "d0cf11e0a1b11ae1" ascii nocase
        $ole3 = "64306366313165306131623131616531" ascii // HEX
        $ole4 = "640a300a630a660a310a310a650a300a610a310a620a310a310a610a650a31" // HEX manipulated
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (1 of ($ex*) and 1 of ($ole*) and 2 of ($obj*))
}

rule INDICATOR_OLE_References_Command_in_Metadata {
    meta:
        description = "Detects OLE documents with Windows command-line utilities commands (certutil, powershell, etc.) stored in the metadata (author, last modified by, etc.)."
        author = "ditekSHen"
    strings:
        // The byte(s) immediately following the anchor "00 00 00 1E 00 00 00" represent 
        // the length of the metadata field. For example: in "00 00 00 1E 00 00 00 08",
        // the "08" is total length of the value of the field, i.e: 8:
        // 00003e00  04 00 00 00 00 00 00 00  1e 00 00 00 >>08 00 00 00  |................|
        // 00003e10  55 73 65 72 00<< 00 00 00  1e 00 00 00 04 00 00 00  |User............|
        // Some variants don't reference the command itself, but following parts 
        $cmd1 = { 00 1E 00 00 00 [1-4] 00 00 63 6D 64 (00|20) }  // |00 00|cmd|00|
        $cmd2 = { 00 1E 00 00 00 [1-4] 00 00 6d 73 68 74 61 (00|20) }  // |00 00|mshta|00|
        $cmd3 = { 00 1E 00 00 00 [1-4] 00 00 77 73 63 72 69 70 74 (00|20) }  // |00 00|wscript|00|
        $cmd4 = { 00 1E 00 00 00 [1-4] 00 00 63 65 72 74 75 74 69 6C (00|20) } // |00 00|certutil|00|
        $cmd5 = { 00 1E 00 00 00 [1-4] 00 00 70 6F 77 65 72 73 68 65 6C 6C (00|20) } // |00 00|powershell|00|
        $cmd6 = { 00 1E 00 00 00 [1-4] 00 00 6E 65 74 2E 77 65 62 63 6C 69 65 6E 74 (00|20) } // |00 00|net.webclient|00|
    condition:
        uint16(0) == 0xcfd0 and filesize < 8000KB and any of them
}

rule INDICATOR_EXPLOIT_RTF_MultiExploit_Embedded_Object_Files {
    meta:
        description = "Detects RTF documents potentially exploting multiple vulnerabilities and embeding next stage scripts and/or binaries"
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq1 = "02ce020000000000c000000000000046" ascii nocase
        $eq2 = { 02ce020000000000c000000000000046 }
        // 00000300-0000-0000-C000-000000000046: OLE2Link
        // CVE-2017-0199, CVE-2017-8570, CVE-2017-8759 or CVE-2018-8174
        $ole2link1 = "03000000000000c000000000000046" ascii nocase
        $ole2link2 = { 03000000000000c000000000000046 }
        $ole2link3 = "4f4c45324c696e6b" ascii nocase // HEX
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\mmath" ascii
        // OLE Package Object
        $pkg = "5061636B616765" ascii nocase
        // Embedded Files Extensions - ASCII
        $emb_exe = { 3265 (3635|3435) (3738|3538) (3635|3435) 3030 }
        $emb_scr = { 3265 (3733|3533) (3633|3433) (3532|3732) 3030 }
        $emb_dll = { 3265 (3634|3434) (3663|3463) (3663|3463) 3030 }
        $emb_doc = { 3265 (3634|3434) (3666|3466) (3633|3433) 3030 }
        $emb_bat = { 3265 (3632|3432) (3631|3431) (3734|3534) 3030 }
        $emb_sct = { 3265 (3733|3533) (3633|3433) (3734|3534) 3030 }
        $emb_txt = { 3265 (3734|3534) (3738|3538) (3734|3534) 3030 }
        $emb_psw = { 3265 (3730|3530) (3733|3533) 313030 }
    condition:
        // Strict: uint32(0) == 0x74725c7b and filesize > 400KB and (1 of ($eq*) or 1 of ($ole2link*)) and $pkg and 2 of ($obj*) and 1 of ($emb*)
        uint32(0) == 0x74725c7b and filesize > 100KB and (1 of ($eq*) or 1 of ($ole2link*)) and $pkg and 2 of ($obj*) and 1 of ($emb*)
}

rule INDICATOR_OLE_ObjectPool_Embedded_Files {
    meta:
        description = "Detects OLE documents with ObjectPool OLE storage and embed suspicous excutable files"
        author = "ditekSHen"
    strings:
        $s1 = "ObjectPool" fullword wide
        $s2 = "Ole10Native" fullword wide
        $s3 = "Root Entry" fullword wide

        $h1 = { 4f 00 62 00 6a 00 65 00 63 00 74 00 50 00 6f 00 6f 00 6c 00 }
        $h2 = { 4f 00 6c 00 65 00 31 00 30 00 4e 00 61 00 74 00 69 00 76 00 65 00 }
        $h3 = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 00 }
        // OLE Package Object
        $olepkg = { 00 00 00 0c 00 03 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        // Embedded Files Extensions - ASCII - Not as reliable as its hex variant
        $fa_exe = ".exe" ascii nocase
        $fa_scr = ".scr" ascii nocase
        $fa_dll = ".dll" ascii nocase
        $fa_bat = ".bat" ascii nocase
        $fa_cmd = ".cmd" ascii nocase
        $fa_sct = ".sct" ascii nocase
        $fa_txt = ".txt" ascii nocase
        $fa_psw = ".ps1" ascii nocase
        // File extensions - Hex > slowing down scanning
        /*
        $fh_exe = { 2e (45|65) (58|78) (45|65) 00 }
        $fh_scr = { 2e (53|73) (43|63) (52|72) 00 }
        $fh_dll = { 2e (44|64) (4c|6c) (4c|6c) 00 }
        $fh_bat = { 2e (42|62) (41|61) (54|74) 00 }
        $fh_cmd = { 2e (43|63) (4d|6d) (44|64) 00 }
        $fh_sct = { 2e (53|73) (43|63) (54|74) 00 }
        $fh_txt = { 2e (54|74) (58|78) (54|74) 00 }
        $fh_psw = { 2e (50|70) (53|73) 31 00 }
        */
    condition:
        uint16(0) == 0xcfd0 and (all of ($s*) or all of ($h*)) and $olepkg and 1 of ($fa*)
}

rule INDICATOR_RTF_Equation_BITSAdmin_Downloader {
    meta:
        description = "Detects RTF documents that references both Microsoft Equation Editor and BITSAdmin. Common exploit + dropper behavior."
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq = "0200000002CE020000000000C000000000000046" ascii nocase
        // BITSAdmin
        $ba = "6269747361646d696e" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (($eq and $ba) and 1 of ($obj*))
}

rule INDICATOR_RTF_Equation_CertUtil_Downloader {
    meta:
        description = "Detects RTF documents that references both Microsoft Equation Editor and CertUtil. Common exploit + dropper behavior."
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq = "0200000002CE020000000000C000000000000046" ascii nocase
        // CertUtil
        $cu = "636572747574696c" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (($eq and $cu) and 1 of ($obj*))
}

rule INDICATOR_RTF_Equation_PowerShell_Downloader {
    meta:
        description = "Detects RTF documents that references both Microsoft Equation Editor and PowerShell. Common exploit + dropper behavior."
        author = "ditekSHen"
    strings:
        // 0002CE02-0000-0000-C000-000000000046: Equation
        // CVE-2017-11882 or CVE-2018-0802
        $eq = "0200000002CE020000000000C000000000000046" ascii nocase
        // PowerShell
        $ps = "706f7765727368656c6c" ascii nocase
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
    condition:
        uint32(0) == 0x74725c7b and (($ps and $eq) and 1 of ($obj*))
}

rule INDICATOR_RTF_LNK_Shell_Explorer_Execution {
    meta:
        description = "detects RTF files with Shell.Explorer.1 OLE objects with embedded LNK files referencing an executable."
        author = "ditekSHen"
    strings:
        // Shell.Explorer.1 OLE Object CLSID
        $clsid = "c32ab2eac130cf11a7eb0000c05bae0b" ascii nocase
        // LNK Shortcut Header
        $lnk_header = "4c00000001140200" ascii nocase
        // Second Stage Artefacts - http/file
        $http_url = "6800740074007000" ascii nocase
        $file_url = "660069006c0065003a" ascii nocase
    condition:
        uint32(0) == 0x74725c7b and filesize < 1500KB and $clsid and $lnk_header and ($http_url or $file_url)
}

rule INDICATOR_RTF_Forms_HTML_Execution {
    meta:
        description = "detects RTF files with Forms.HTML:Image.1 or Forms.HTML:Submitbutton.1 OLE objects referencing file or HTTP URLs."
        author = "ditekSHen"
    strings:
        // Forms.HTML:Image.1 OLE Object CLSID
        $img_clsid = "12d11255c65ccf118d6700aa00bdce1d" ascii nocase
        // Forms.HTML:Submitbutton.1 Object CLSID
        $sub_clsid = "10d11255c65ccf118d6700aa00bdce1d" ascii nocase
        // Second Stage Artefacts - http/file
        $http_url = "6800740074007000" ascii nocase
        $file_url = "660069006c0065003a" ascii nocase
    condition:
        uint32(0) == 0x74725c7b and filesize < 1500KB and ($img_clsid or $sub_clsid) and ($http_url or $file_url)
}

rule INDICATOR_PUB_MSIEXEC_Remote {
    meta:
        description = "detects VB-enable Microsoft Publisher files utilizing Microsoft Installer to retrieve remote files and execute them"
        author = "ditekSHen"
    strings:
        $s1 = "Microsoft Publisher" ascii
        $s2 = "msiexec.exe" ascii
        $s3 = "Document_Open" ascii
        $s4 = "/norestart" ascii
        $s5 = "/i http" ascii
        $s6 = "Wscript.Shell" fullword ascii
        $s7 = "\\VBE6.DLL#" wide
    condition:
        uint16(0) == 0xcfd0 and filesize < 200KB and 6 of them
}

rule INDICATOR_RTF_Ancalog_Exploit_Builder_Document {
    meta:
        description = "Detects documents generated by Phantom Crypter/Ancalog"
        author = "ditekSHen"
    strings:
        $builder1 = "{\\*\\ancalog" ascii
        $builder2 = "\\ancalog" ascii
    condition:
        uint32(0) == 0x74725c7b and 1 of ($builder*)
}

rule INDICATOR_RTF_ThreadKit_Exploit_Builder_Document {
    meta:
        description = "Detects vaiations of RTF documents generated by ThreadKit builder."
        author = "ditekSHen"
    strings:
        // Embedded Objects
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii
        $obj7 = "\\mmath" ascii
        // Patterns
        $pat1 = /\\objupdate\\v[\\\s\n\r]/ ascii
    condition:
        uint32(0) == 0x74725c7b and 2 of ($obj*) and 1 of ($pat*)
}

rule INDICATOR_XML_LegacyDrawing_AutoLoad_Document {
    meta:
        description = "detects AutoLoad documents using LegacyDrawing"
        author = "ditekSHen"
    strings:
        $s1 = "<legacyDrawing r:id=\"" ascii
        $s2 = "<oleObject progId=\"" ascii
        $s3 = "autoLoad=\"true\"" ascii
    condition:
        uint32(0) == 0x6d783f3c and all of ($s*)
}

rule INDICATOR_XML_OLE_AutoLoad_Document {
    meta:
        description = "detects AutoLoad documents using OLE Object"
        author = "ditekSHen"
    strings:
        $s1 = "autoLoad=\"true\"" ascii
        $s2 = "/relationships/oleObject\"" ascii
        $s3 = "Target=\"../embeddings/oleObject" ascii
    condition:
        uint32(0) == 0x6d783f3c and all of ($s*)
}

rule Indicator_XML_Squiblydoo_1 {
    meta:
        description = "detects Squiblydoo variants extracted from exploit RTF documents."
        author = "ditekSHen"
    strings:
        $slt = "<scriptlet" ascii
        $ws1 = "CreateObject(\"WScript\" & \".Shell\")" ascii
        $ws2 = "CreateObject(\"WScript.Shell\")" ascii
        $ws3 = "ActivexObject(\"WScript.Shell\")" ascii
        $r1 = "[\"run\"]" nocase ascii
        $r2 = ".run \"cmd" nocase ascii
        $r3 = ".run chr(" nocase ascii
    condition:
        (uint32(0) == 0x4d583f3c or uint32(0) == 0x6d783f3c) and $slt and 1 of ($ws*) and 1 of ($r*)
}

rule INDICATOR_OLE_Suspicious_Reverse {
     meta:
        description = "detects OLE documents containing VB scripts with reversed suspicious strings"
        author = "ditekSHen"
    strings:
        // Uses VB
        $vb = "\\VBE7.DLL" ascii
        // Command-line Execution
        $cmd1 = "CMD C:\\" nocase ascii
        $cmd2 = "CMD /c " nocase ascii
        // Suspicious Keywords
        $kw1 = "]rAHC[" nocase ascii
        $kw2 = "ekOVNI" nocase ascii
        $kw3 = "EcaLPEr" nocase ascii
        $kw4 = "TcEJBO-WEn" nocase ascii
        $kw5 = "eLbAirav-Teg" nocase ascii
        $kw6 = "ReveRSE(" nocase ascii
        $kw7 = "-JOIn" nocase ascii
    condition:
        uint16(0) == 0xcfd0 and $vb and ((1 of ($cmd*) and 1 of ($kw*)) or (2 of ($kw*)))
}

rule INDICATOR_OLE_Suspicious_ActiveX {
    meta:
        description = "detects OLE documents with suspicious ActiveX content"
        author = "ditekSHen"
    strings:
        // Uses VB
        $vb = "\\VBE7.DLL" ascii
        // ActiveX Control Objects > Triggers
        $ax1 = "_Layout" ascii
        $ax2 = "MultiPage1_" ascii
        $ax3 = "_MouseMove" ascii
        $ax4 = "_MouseHover" ascii
        $ax5 = "_MouseLeave" ascii
        $ax6 = "_MouseEnter" ascii
        $ax7 = "ImageCombo21_Change" ascii
        $ax8 = "InkEdit1_GotFocus" ascii
        $ax9 = "InkPicture1_" ascii
        $ax10 = "SystemMonitor1_" ascii
        $ax11 = "WebBrowser1_" ascii
        $ax12 = "_Click" ascii
        // Suspicious Keywords
        $kw1 = "CreateObject" ascii
        $kw2 = "CreateTextFile" ascii
        $kw3 = ".SpawnInstance_" ascii
        $kw4 = "WScript.Shell" ascii
        $kw5 = { 43 68 72 [0-2] 41 73 63 [0-2] 4d 69 64 }    // & Chr(Asc(Mid(
        $kw6 = { 43 68 [0-2] 72 24 28 40 24 28 22 26 48 }    // & Chr$(Val("&H"
        $kw7 = { 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 } // ActiveDocument
    condition:
        uint16(0) == 0xcfd0 and $vb and 1 of ($ax*) and 2 of ($kw*)
}

rule INDICATOR_OLE_Suspicious_MITRE_T1117 {
    meta:
        description = "Detects MITRE technique T1117 in OLE documents"
        author = "ditekSHen"
    strings:
        $s1 = "scrobj.dll" ascii
        $s2 = "regsvr32" ascii
        $s3 = "JyZWdzdnIzMi5leGU" ascii
        $s4 = "HNjcm9iai5kbGw" ascii
    condition:
        uint16(0) == 0xcfd0 and 2 of them
}

rule INDICATOR_OLE_RemoteTemplate {
    meta:
        description = "Detects XML relations where an OLE object is refrencing an external target in dropper OOXML documents"
        author = "ditekSHen"
    strings:
        $olerel = "relationships/oleObject" ascii
        $target1 = "Target=\"http" ascii
        $target2 = "Target=\"file" ascii
        $mode = "TargetMode=\"External" ascii
    condition:
        $olerel and $mode and 1 of ($target*)
}