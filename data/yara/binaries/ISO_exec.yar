rule ISO_exec
{
    meta:
        description = "Identifies execution artefacts in ISO files, seen in malware such as Bumblebee."
        author = "@bartblaze"
        date = "2022-07-29"
        tlp = "Clear"
        
strings:
       $ = "\\System32\\cmd.exe" ascii wide nocase
       $ = "\\System32\\rundll32.exe" ascii wide nocase
       $ = "OSTA Compressed Unicode" ascii wide
       $ = "UDF Image Creator" ascii wide

condition:
       uint16(0) != 0x5a4d and 3 of them
}
