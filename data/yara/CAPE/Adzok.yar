rule Adzok
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		Description = "Adzok Rat"
		Versions = "Free 1.0.0.3,"
		ref = "http://malwareconfig.com/stats/Adzok"
		maltype = "Remote Access Trojan"
		filetype = "jar"
        cape_type = "Adzok Payload"

	strings:
		$a1 = "config.xmlPK"
		$a2 = "key.classPK"
		$a3 = "svd$1.classPK"
		$a4 = "svd$2.classPK"
   		$a5 = "Mensaje.classPK"
		$a6 = "inic$ShutdownHook.class"
		$a7 = "Uninstall.jarPK"
		$a8 = "resources/icono.pngPK"
        
	condition:
    		7 of ($a*)
}