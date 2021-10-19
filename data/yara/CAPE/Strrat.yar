rule Strrat
{
	meta:
		author = "enzo"
		description = "Strrat Rat"
		cape_type = "Strrat Payload"
	strings:
		$string1 = "config.txt" ascii
		$string2 = "carLambo" ascii
		$string3 = "META-INF" ascii
		$string4 = "Allatori"
	condition:
		all of them
}
