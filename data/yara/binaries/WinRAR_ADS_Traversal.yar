rule WinRAR_ADS_Traversal
{
    meta:
      description = "Identifies potential ADS traversal in RAR archives."
    	author = "@bartblaze"
    	date = "2025-08"
    	tlp = "White"

    strings:
        $rar= { 52 61 72 21 }
        $ads_traversal = ":..\\..\\..\\..\\..\\..\\..\\..\\" ascii wide nocase
        $zone_identifier = "Zone.Identifier" ascii wide nocase
        $lnk = ".lnk" ascii wide nocase
        $bat = ".bat" ascii wide nocase
        $vbs = ".vbs" ascii wide nocase
        $js = ".js" ascii wide nocase
        $exe = ".exe" ascii wide nocase
 
    condition:
        $rar at 0 and $ads_traversal
        and not $zone_identifier
        and any of ($lnk, $bat, $vbs, $js, $exe)
}
