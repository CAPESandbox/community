rule MalScript_Tricks
{
meta:
	description = "Identifies tricks often seen in malicious scripts such as moving the window off-screen or resizing it to zero."
	author = "@bartblaze"
	date = "2020-12"
	tlp = "White"

strings:
	$s1 = "window.moveTo -" ascii wide nocase
	$s2 = "window.resizeTo 0" ascii wide nocase

	$x1 = "window.moveTo(-" ascii wide nocase
	$x2 = "window.resizeTo(" ascii wide nocase

condition:
	filesize <50KB and ( all of ($s*) or all of ($x*) )
}
