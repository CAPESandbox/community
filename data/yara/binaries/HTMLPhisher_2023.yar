/*
   YARA Rule Set for HTML phishing
   Author: Yasin Tas, Eye Security
   Date: 2023-04-05
   Identifier: HTMLPhisher_2023
   Reference: Personal Research
*/

rule susp_documentwrite_HTML {
   meta:
      description = "Detection for document.write in HTML files"
      author = "Yasin Tas, Eye Security"
      reference = "Personal Research"

   strings:
      $html_magic0 = { 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E }
      $html_magic1 = { 3C 68 74 6D 6C 3E }
      $script_magic0 = { 3C 73 63 72 69 70 74 3E }
      $script_magic1 = { 3C 73 63 72 69 70 74 20 }
      $document_write = { 64 6F 63 75 6D 65 6E 74 2E 77 72 69 74 65 }
   condition:
      ($html_magic0 at 0 or $html_magic1 at 0 or $script_magic0 at 0 or $script_magic1 at 0)
      and $document_write 
}

rule susp_obfuscated_HTML_atob_btoa {
   meta:
      description = "Detection for JS atob in HTML files"
      author = "Yasin Tas, Eye Security"
      reference = "Personal Research"

   strings:
      $html_magic0 = { 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E }
      $html_magic1 = { 3C 68 74 6D 6C 3E }
      $script_magic0 = { 3C 73 63 72 69 70 74 3E }
      $script_magic1 = { 3C 73 63 72 69 70 74 20 }
      $atob = { 61 74 6f 62 }
      $btoa = { 62 74 6f 61 }
   condition:
      ($html_magic0 at 0 or $html_magic1 at 0 or $script_magic0 at 0 or $script_magic1 at 0)
      and ($atob or $btoa) 
}

rule susp_obfuscated_HTML_eval {
   meta:
      description = "Detection for JS eval in HTML files"
      author = "Yasin Tas, Eye Security"
      reference = "Personal Research"

   strings:
      $html_magic0 = { 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E }
      $html_magic1 = { 3C 68 74 6D 6C 3E }
      $script_magic0 = { 3C 73 63 72 69 70 74 3E }
      $script_magic1 = { 3C 73 63 72 69 70 74 20 }
      $eval = { 65 76 61 6c }
   condition:
      ($html_magic0 at 0 or $html_magic1 at 0 or $script_magic0 at 0 or $script_magic1 at 0)
      and ($eval)
}

rule susp_obfuscated_HTML_fromCharCode {
   meta:
      description = "Detection for JS fromCharcode in HTML files"
      author = "Yasin Tas, Eye Security"
      reference = "Personal Research"

   strings:
      $html_magic0 = { 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E }
      $html_magic1 = { 3C 68 74 6D 6C 3E }
      $script_magic0 = { 3C 73 63 72 69 70 74 3E }
      $script_magic1 = { 3C 73 63 72 69 70 74 20 }
      $fromCharCode = { 66 72 6f 6d 43 68 61 72 43 6f 64 65 }
   condition:
      ($html_magic0 at 0 or $html_magic1 at 0 or $script_magic0 at 0 or $script_magic1 at 0)
      and $fromCharCode
}

rule susp_obfuscated_HTML_unescape_escape {
   meta:
      description = "Detection for JS escape or unescape in HTML files"
      author = "Yasin Tas, Eye Security"
      reference = "Personal Research"

   strings:
      $html_magic0 = { 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E }
      $html_magic1 = { 3C 68 74 6D 6C 3E }
      $script_magic0 = { 3C 73 63 72 69 70 74 3E }
      $script_magic1 = { 3C 73 63 72 69 70 74 20 }
      $unescape = { 75 6e 65 73 63 61 70 65 }
      $escape = { 65 73 63 61 70 65 }
   condition:
      ($html_magic0 at 0 or $html_magic1 at 0 or $script_magic0 at 0 or $script_magic1 at 0)
      and ($unescape or $escape)
}

rule susp_obfuscated_HTML_decodeURIComponent {
   meta:
      description = "Detection for JS decodeURIComponent in HTML files"
      author = "Yasin Tas, Eye Security"
      reference = "Personal Research"

   strings:
      $html_magic0 = { 3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C 3E }
      $html_magic1 = { 3C 68 74 6D 6C 3E }
      $script_magic0 = { 3C 73 63 72 69 70 74 3E }
      $script_magic1 = { 3C 73 63 72 69 70 74 20 }
      $decodeURIComponent = { 64 65 63 6f 64 65 55 52 49 43 6f 6d 70 6f 6e 65 6e 74 }
   condition:
      ($html_magic0 at 0 or $html_magic1 at 0 or $script_magic0 at 0 or $script_magic1 at 0)
      and $decodeURIComponent
}
