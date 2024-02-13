rule EXE_in_LNK
{
meta:
	description = "Identifies executable artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = ".exe" ascii wide nocase
	$ = ".dll" ascii wide nocase
	$ = ".scr" ascii wide nocase
	$ = ".pif" ascii wide nocase
	$ = "This program" ascii wide nocase
	$ = "TVqQAA" ascii wide nocase //MZ Base64
condition:
	isLNK and any of them
}

rule Long_RelativePath_LNK
{
meta:
	description = "Identifies shortcut (LNK) file with a long relative path. Might be used in an attempt to hide the path."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "..\\..\\..\\..\\" ascii wide nocase
condition:
	isLNK and any of them
}

rule MSOffice_in_LNK
{
meta:
	description = "Identifies Microsoft Office artefacts in shortcut (LNK) files."
	author = "@bartblaze"
	date = "2020-01"
	tlp = "White"
strings:
	$ = "winword" ascii wide nocase
	$ = "excel" ascii wide nocase
	$ = "powerpnt" ascii wide nocase
	$ = ".rtf" ascii wide nocase
	$ = ".doc" ascii wide nocase //.doc and .docx
	$ = ".dot" ascii wide nocase //.dot and .dotm
	$ = ".xls" ascii wide nocase //.xls and .xlsx
	$ = ".xla" ascii wide nocase
	$ = ".csv" ascii wide nocase
	$ = ".ppt" ascii wide nocase //.ppt and .pptx
	$ = ".pps" ascii wide nocase //.pps and .ppsx
	$ = ".xml" ascii wide nocase
condition:
	isLNK and any of them
}
