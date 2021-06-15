rule Strrat
{
	meta:
		author = "enzo"
		description = "Strrat Rat"
		cape_type = "Strrat Payload"
	strings:
		$string1 = "strigoi" ascii
		$string2 = "config.txt" ascii
		$string3 = "server" ascii
	condition:
		all of them
}
