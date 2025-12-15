rule GrimResource
{
    meta:
        description = "Identifies GrimResource and potential derivatives or variants."
        author = "@bartblaze"
        tlp = "Clear"
        reference = "https://www.elastic.co/security-labs/grimresource"

    strings:
        $xml = "<?xml"

        $grim_a = "MMC_ConsoleFile"
        $grim_b = ".loadXML("

        $other_a = "ActiveXObject"
        $other_b = "ms:script"
        $other_c = "CDATA"

    condition:
        $xml at 0 and (all of ($grim_*) or all of ($other_*))
}
