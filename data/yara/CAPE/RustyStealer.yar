rule RustyStealer {
    meta:
        author = "ditekSHen"
        description = "Detect Rusty / Luca stealer"
        cape_type = "RustyStealer Payload"
    strings:
        $s1 = "EdgeMicrosoftedgechromiumChromium7star7StaramigoAmigobraveBrave" ascii
        $s2 = "BrowserchromeChromekometaKometaorbitumOrbitumsputnikSputniktorchTorchucozmediaUranuCozMediavivaldiVivaldiatom" ascii
        $s3 = ".kdbx.pdf.doc.docx.xls.xlsx.ppt.pptx.odt.odp\\logscx\\sensfiles.zip" ascii
        $s4 = "dumper.rs" ascii
        $s5 = "decryption_core.rs" ascii
        $s6 = "anti_emulation.rs" ascii
        $s7 = "discord.rs" ascii
        $s8 = /\\logscx\\(passwords_|cookies_|creditcards_)/ ascii
        $s9 = "VirtualBoxVBoxVMWareVMCountry" ascii
        $s10 = "New Log From ( /  )" ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
