import "pe"
rule Amadey {
    meta:
        author = "Rony"
        description = "Detects Amadey Downloader"
        cape_type = "Amadey Payload"
    strings:
        $pdb = "Amadey.pdb" fullword nocase
    condition:
        pe.is_pe and $pdb
}
