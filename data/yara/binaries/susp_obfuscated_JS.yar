rule SUSP_obfuscated_JS_obfuscatorio
{
	meta:

		author      = "@imp0rtp3"
		description = "Detect JS obfuscation done by the js obfuscator (often malicious)"
		reference   = "https://obfuscator.io"

	strings:
		// Beggining of the script
		$a1 = "var a0_0x"
		$a2 = /var _0x[a-f0-9]{4}/
		
		// Strings to search By number of occurences
		$b1 = /a0_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)/
		$b2 =/[^\w\d]_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)[^\w\d]/
		$b3 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\['push'\]\(_0x([a-f0-9]{2}){2,4}\['shift'\]\(\)[^\w\d]/
		$b4 = /!0x1[^\d\w]/
		$b5 = /[^\w\d]function\((_0x([a-f0-9]{2}){2,4},)+_0x([a-f0-9]{2}){2,4}\)\s?\{/
		$b6 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\s?=\s?_0x([a-f0-9]{2}){2,4}[^\w\d]/
		
		// generic strings often used by the obfuscator
		$c1 = "))),function(){try{var _0x"
		$c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$c3 = "['atob']=function("
		$c4 = ")['replace'](/=+$/,'');var"
		$c5 = "return!![]"
		$c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'"
		$c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64
		$c8 = "while(!![])"
		$c9 = "while (!![])"
		// Strong strings
		$d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/
				
	condition:
		$a1 at 0 or
		$a2 at 0 or
		(
			filesize<1000000 and
			(
				(#b1 + #b2) > (filesize \ 200) or
				#b3 > 1 or
				#b4 > 10 or
				#b5 > (filesize \ 2000) or
				#b6 > (filesize \ 200) or
				3 of ($c*) or
				$d1
			)
		)
}