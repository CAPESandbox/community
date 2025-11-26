rule Prometei
{
    meta:
        description = "Identifies Prometei botnet main modules."
        author = "@bartblaze"
        date = "2023-03-24"
        tlp = "Clear"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.prometei"
        cape_type = "Prometei payload"

    strings:
        $ = "prometeicmd" ascii wide fullword
        $ = "/cgi-bin/prometei.cgi" ascii wide
    
    condition:
        any of them
}
