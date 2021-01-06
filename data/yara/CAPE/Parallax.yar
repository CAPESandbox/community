rule Parallax
{
meta:
	description = "Identifies Parallax RAT."
	author = "@bartblaze"
	date = "2020-09"
	tlp = "White"
    cape_type = "Parallax Payload"

strings:
	$ = ".DeleteFile(Wscript.ScriptFullName)" ascii wide
	$ = ".DeleteFolder" ascii wide fullword
	$ = ".FileExists" ascii wide fullword
	$ = "= CreateObject" ascii wide fullword
	$ = "Clipboard Start" ascii wide fullword
	$ = "UN.vbs" ascii wide fullword
	$ = "[Alt +" ascii wide fullword
	$ = "[Clipboard End]" ascii wide fullword
	$ = "[Ctrl +" ascii wide fullword

condition:
	4 of them
}
