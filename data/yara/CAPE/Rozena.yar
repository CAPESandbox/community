rule Rozena
{
    meta:
        author = "VXREMALWARE"
        threat_name = "Linux.Trojan.Rozena"
        reference_sample = "997684fb438af3f5530b0066d2c9e0d066263ca9da269d6a7e160fa757a51e04"
        maltype = "Remote Access Trojan"
	filetype = "exe"
    cape_type = "Rozena Payload"
    strings:
        $p = { 89 E1 95 68 A4 1A 70 C7 57 FF D6 6A 10 51 55 FF D0 68 A4 AD }
    condition:
        all of them
}
