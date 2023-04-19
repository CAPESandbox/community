/*
   YARA Rule Set for OneNote Files  
*/
rule susp_embedded_OneNote_files{
   meta:
      description = "Detects suspicious embedded files in OneNote files"
      author = "Yasin Tas, Eye Security"
      reference = "Personal Research"
      date = "2023-01-27"
   
   strings:
      //

   condition:
      any of them
}
rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_1 {
   meta:
      description = "Detects suspicious OneNote attachment that embeds suspicious payload, e.g. an executable (FPs possible if the PE is attached separately)"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2023-01-27"
      score = 65
   strings:
      /* OneNote FileDataStoreObject GUID https://blog.didierstevens.com/ */
      $ge1 = "5xbjvWUmEUWkxI1NC3qer"
      $ge2 = "cW471lJhFFpMSNTQt6nq"
      $ge3 = "nFuO9ZSYRRaTEjU0Lep6s"
      /* PE file DOS header */
      $sp1 = "VGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZG"
      $sp2 = "RoaXMgcHJvZ3JhbSBjYW5ub3QgYmUgcnVuIGluIERPUyBtb2Rl"
      $sp3 = "UaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZ"
      $sp4 = "VGhpcyBwcm9ncmFtIG11c3QgYmUgcnVuIHVuZGVy"
      $sp5 = "RoaXMgcHJvZ3JhbSBtdXN0IGJlIHJ1biB1bmRlc"
      $sp6 = "UaGlzIHByb2dyYW0gbXVzdCBiZSBydW4gdW5kZX"
      /* @echo off */
      $se1 = "QGVjaG8gb2Zm"
      $se2 = "BlY2hvIG9mZ"
      $se3 = "AZWNobyBvZm"
      /* <HTA:APPLICATION */
      $se4 = "PEhUQTpBUFBMSUNBVElPTi"
      $se5 = "xIVEE6QVBQTElDQVRJT04g"
      $se6 = "8SFRBOkFQUExJQ0FUSU9OI"
      /* LNK file magic header */
      $se7 = "TAAAAAEUAg"
      $se8 = "wAAAABFAIA"
      $se9 = "MAAAAARQCA"
   condition:
      filesize < 5MB
      and 1 of ($ge*)
      and 1 of ($s*)
}

rule SUSP_Email_Suspicious_OneNote_Attachment_Jan23_2 {
   meta:
      description = "Detects suspicious OneNote attachment that has a file name often used in phishing attacks"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2023-01-27"
      score = 65
   strings:
      /* .one\n\n5FJce */
      $hc1 = { 2E 6F 6E 65 22 0D 0A 0D 0A 35 46 4A 63 65 }
      $x01 = " attachment; filename=\"Invoice" nocase
      $x02 = " attachment; filename=\"ORDER" nocase
      $x03 = " attachment; filename=\"PURCHASE" nocase
      $x04 = " attachment; filename=\"SHIP" nocase
   condition:
      filesize < 5MB 
      and $hc1 
      and 1 of ($x*)
}

rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_1 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      modified = "2023-02-27"
      score = 65
   strings:
      /* GUID FileDataStoreObject https://blog.didierstevens.com/ */
      $x1 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4d 5a } // PE
      $x2 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 65 63 68 6f } // @echo off
      $x3 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 40 45 43 48 4f } // @ECHO OFF
      $x4 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 4F 6E 20 45 } // On Error Resume
      $x5 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac 
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [0-4] 6F 6E 20 65 } // on error resume
      $x6 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 4c 00 00 00 } // LNK file
      $x7 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? 49 54 53 46 } // CHM file
      $x8 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 68 74 61 3A } // hta:
      $x9 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 48 54 41 3A } // HTA:
      $x10 = { e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac
              ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??
              ?? ?? ?? ?? [6-200] 3C 6A 6F 62 20 } // WSF file "<job "
   condition:
      filesize < 10MB and 1 of them
}

rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_2 {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27"
      score = 65
   strings:
      /* GUID FileDataStoreObject https://blog.didierstevens.com/ */
      $a1 = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }
      $s1 = "<HTA:APPLICATION "
   condition:
      filesize < 5MB
      and $a1 
      and 1 of ($s*)
}   

rule SUSP_OneNote_Win_Script_Encoding_Feb23 {
   meta:
      description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
      author = "delivr.to"
      date = "2023-02-19"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* Windows Script Encoding Header */
      $wse = { 23 40 7E 5E }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      $wse
}

rule SUSP_OneNote_Repeated_FileDataReference_Feb23 {
   meta:
      description = "Repeated references to files embedded in OneNote file. May indicate multiple copies of file hidden under image, as leveraged by Qakbot et al."
      author = "delivr.to"
      date = "2023-02-17"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* FileDataReference <ifndf>{GUID} */
      /* https://interoperability.blob.core.windows.net/files/MS-ONESTORE/%5bMS-ONESTORE%5d.pdf */
      $fref = { 3C 00 69 00 66 00 6E 00 64 00 66 00 3E 00 7B 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 2D 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? 00 ?? }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      #fref > (#fdso * 4)
}

rule SUSP_OneNote_RTLO_Character_Feb23 {
   meta:
      description = "Presence of RTLO Unicode Character in a OneNote file with embedded files"
      author = "delivr.to"
      date = "2023-02-17"
      score = 60
   strings:
      /* [MS-ONESTORE] File Header */
      $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }

      /* FileDataStoreObject GUID */
      $fdso = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac }

      /* RTLO */
      $rtlo = { 00 2E 20 }

   condition:
      filesize < 5MB and
      ($one at 0) and 
      $fdso and
      $rtlo
}

rule OneNote_EmbeddedFiles_NoPictures
{
    meta:
        author = "Nicholas Dhaeyer - @DhaeyerWolf"
        date_created = "2023-02-14 - <3"
        date_last_modified = "2023-02-17"
        description = "OneNote files that contain embedded files that are not pictures."
        reference = "https://blog.didierstevens.com/2023/01/22/analyzing-malicious-onenote-documents/"
		yarahub_uuid = "d0c4f0e6-adbe-4953-a2df-91427a561e97"
		date = "2023-02-14"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "52486a446dd4fc5842a47b57d3febec7"

    strings:
		$start = { e4 52 5c 7b 8c d8 a7 4d ae b1 53 78 d0 29 96 d3 } //beginning of a OneNote file
	
        $EmbeddedFileGUID =  { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC }
        $PNG = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 89 50 4E 47 0D 0A 1A 0A }
        $JPG = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 FF D8 FF }
        $JPG20001 = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 6A 50 20 20 0D 0A 87 0A }
        $JPG20002 = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 FF 4F FF 51 }
        $BMP = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 42 4D }
        $GIF = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 47 49 46 }

    condition:
        $start at 0 and $EmbeddedFileGUID and (#EmbeddedFileGUID > #PNG + #JPG + #JPG20001 + #JPG20002 + #BMP + #GIF)
}

rule OneNote_Malicious_Paths
{
	meta:
        author = "Nicholas Dhaeyer - @DhaeyerWolf"
        date_created = "2023-02-23"
        date_last_modified = "2023-02-23"
        description = "Looks for OneNote Files with known malicious strings"
		
    strings:
		$start = { e4 52 5c 7b 8c d8 a7 4d ae b1 53 78 d0 29 96 d3 } //beginning of a OneNote file
		
		//Start of malicious strings
		$hex_string1 = { 5a 00 3a 00 5c 00 62 00 75 00 69 00 6c 00 64 00 65 00 72 00 5c } // Z:\builder\
		$hex_string2 = { 5a 00 3a 00 5c 00 62 00 75 00 69 00 6c 00 64 00 5c } // Z:\build\
		
    condition:
        $start at 0 and ($hex_string1 or $hex_string2)
}

rule OneNote_BuildPath
{
    meta:
        id = "6lPn0V5wZyc2iuEz13uKAZ"
        fingerprint = "f8ed9e3cdd5411e2bda7495c8b00b8e69e8f495db97cf542f6a1f3b790bef7a5"
        version = "1.0"
        first_imported = "2023-02-02"
        last_modified = "2023-02-23"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies malicious OneNote file by build path."
        category = "MALWARE"

strings:
	//Z:\build\one\attachment.hta
	$path_0 = {5a003a005c006200750069006c0064005c006f006e0065005c006100740074006100630068006d0065006e0074002e00680074006100}
	//Z:\builder\O P E N.wsf
	$path_1 = {5a003a005c006200750069006c006400650072005c004f00200050002000450020004e002e00770073006600}
condition:
	filesize <200KB and any of them
}