import "pe"

rule INDICATOR_SUSPICIOUS_Ransomware {
    meta:
        description = "detects command variations typically used by ransomware"
        author = "ditekSHen"
    strings:
        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all /quiet" ascii wide nocase
        $cmd3 = "vssadmin Delete Shadows /all /quiet" ascii wide nocase
        $cmd4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $cmd5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $wp1 = "wbadmin delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "wbadmin delete systemstatebackup" ascii wide nocase
    condition:
        (uint16(0) == 0x5a4d and 2 of ($cmd*) or (1 of ($cmd*) and 1 of ($wp*))) or (4 of them)
}

rule INDICATOR_SUSPICIOUS_ReflectiveLoader {
    meta:
        description = "detects Reflective DLL injection artifacts"
        author = "ditekSHen"
    strings:
        $s1 = "_ReflectiveLoader@" ascii wide
        $s2 = "ReflectiveLoader@" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of them or (
            pe.exports("ReflectiveLoader@4") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("ReflectiveLoader")
            )
        )
}

rule INDICATOR_SUSPICIOUS_IMG_Embedded_Archive {
    meta:
        description = "Detects images embedding archives. Observed in TheRat RAT."
        author = "@ditekSHen"
    strings:
        $sevenzip1 = { 37 7a bc af 27 1c 00 04 } // 7ZIP, regardless of password-protection
        $sevenzip2 = { 37 e4 53 96 c9 db d6 07 } // 7ZIP zisofs compression format    
        $zipwopass = { 50 4b 03 04 14 00 00 00 } // None password-protected PKZIP
        $zipwipass = { 50 4b 03 04 33 00 01 00 } // Password-protected PKZIP
        $zippkfile = { 50 4b 03 04 0a 00 02 00 } // PKZIP
        $rarheade1 = { 52 61 72 21 1a 07 01 00 } // RARv4
        $rarheade2 = { 52 65 74 75 72 6e 2d 50 } // RARv5
        $rarheade3 = { 52 61 72 21 1a 07 00 cf } // RAR
        $mscabinet = { 4d 53 46 54 02 00 01 00 } // Microsoft cabinet file
        $zlockproe = { 50 4b 03 04 14 00 01 00 } // ZLock Pro encrypted ZIP
        $winzip    = { 57 69 6E 5A 69 70 }       // WinZip compressed archive 
        $pklite    = { 50 4B 4C 49 54 45 }       // PKLITE compressed ZIP archive
        $pksfx     = { 50 4B 53 70 58 }          // PKSFX self-extracting executable compressed file
    condition:
        // JPEG or JFIF or PNG or BMP
        (uint32(0) == 0xe0ffd8ff or uint32(0) == 0x474e5089 or uint16(0) == 0x4d42) and 1 of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EventViewer {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using eventvwr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
        $s2 = "eventvwr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CleanMgr {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using cleanmgr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Enviroment\\windir" ascii wide nocase
        $s2 = "\\system32\\cleanmgr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_Enable_OfficeMacro {
    meta:
        description = "Detects Windows executables referencing Office macro registry keys. Observed modifying Office configurations via the registy to enable macros"
        author = "@ditekSHen"
    strings:
        $s1 = "\\Word\\Security\\VBAWarnings" ascii wide
        $s2 = "\\PowerPoint\\Security\\VBAWarnings" ascii wide
        $s3 = "\\Excel\\Security\\VBAWarnings" ascii wide

        $h1 = "5c576f72645c53656375726974795c5642415761726e696e6773" nocase ascii wide
        $h2 = "5c506f776572506f696e745c53656375726974795c5642415761726e696e6773" nocase ascii wide
        $h3 = "5c5c457863656c5c5c53656375726974795c5c5642415761726e696e6773" nocase ascii wide

        $d1 = "5c%57%6f%72%64%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
        $d2 = "5c%50%6f%77%65%72%50%6f%69%6e%74%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
        $d3 = "5c%5c%45%78%63%65%6c%5c%5c%53%65%63%75%72%69%74%79%5c%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_Disable_OfficeProtectedView {
    meta:
        description = "Detects Windows executables referencing Office ProtectedView registry keys. Observed modifying Office configurations via the registy to disable ProtectedView"
        author = "@ditekSHen"
    strings:
        $s1 = "\\Security\\ProtectedView\\DisableInternetFilesInPV" ascii wide
        $s2 = "\\Security\\ProtectedView\\DisableAttachementsInPV" ascii wide
        $s3 = "\\Security\\ProtectedView\\DisableUnsafeLocationsInPV" ascii wide

        $h1 = "5c53656375726974795c50726f746563746564566965775c44697361626c65496e7465726e657446696c6573496e5056" nocase ascii wide
        $h2 = "5c53656375726974795c50726f746563746564566965775c44697361626c65417474616368656d656e7473496e5056" nocase ascii wide
        $h3 = "5c53656375726974795c50726f746563746564566965775c44697361626c65556e736166654c6f636174696f6e73496e5056" nocase ascii wide

        $d1 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%49%6e%74%65%72%6e%65%74%46%69%6c%65%73%49%6e%50%56" nocase ascii
        $d2 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%41%74%74%61%63%68%65%6d%65%6e%74%73%49%6e%50%56" nocase ascii
        $d3 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%55%6e%73%61%66%65%4c%6f%63%61%74%69%6f%6e%73%49%6e%50%56" nocase ascii
    condition:
         uint16(0) == 0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxProductID {
    meta:
        description = "Detects binaries and memory artifcats referencing sandbox product IDs"
        author = "ditekSHen"
    strings:
        $id1 = "76487-337-8429955-22614" fullword ascii wide // Anubis Sandbox
        $id2 = "76487-644-3177037-23510" fullword ascii wide // CW Sandbox
        $id3 = "55274-640-2673064-23950" fullword ascii wide // Joe Sandbox
        $id4 = "76487-640-1457236-23837" fullword ascii wide // Anubis Sandbox
        $id5 = "76497-640-6308873-23835" fullword ascii wide // CWSandbox
        $id6 = "76487-640-1464517-23259" fullword ascii wide // ??
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxHookingDLL {
    meta:
        description = "Detects binaries and memory artifcats referencing sandbox DLLs typically observed in sandbox evasion"
        author = "ditekSHen"
    strings:
        $dll1 = "sbiedll.dll" nocase fullword ascii wide
        // $dll2 = "dbghelp.dll" nocase fullword ascii wide  
        $dll3 = "api_log.dll" nocase fullword ascii wide  
        $dll4 = "pstorec.dll" nocase fullword ascii wide  
        $dll5 = "dir_watch.dll" nocase fullword ascii wide
        $dll6 = "vmcheck.dll" nocase fullword ascii wide  
        $dll7 = "wpespy.dll" nocase fullword ascii wide   
        $dll8 = "SxIn.dll" nocase fullword ascii wide     
        $dll9 = "Sf2.dll" nocase fullword ascii wide     
        $dll10 = "deploy.dll" nocase fullword ascii wide   
        $dll11 = "avcuf32.dll" nocase fullword ascii wide  
        $dll12 = "BgAgent.dll" nocase fullword ascii wide  
        $dll13 = "guard32.dll" nocase fullword ascii wide  
        $dll14 = "wl_hook.dll" nocase fullword ascii wide  
        $dll15 = "QOEHook.dll" nocase fullword ascii wide  
        $dll16 = "a2hooks32.dll" nocase fullword ascii wide
        $dll17 = "tracer.dll" nocase fullword ascii wide
        $dll18 = "APIOverride.dll" nocase fullword ascii wide
        $dll19 = "NtHookEngine.dll" nocase fullword ascii wide
        $dll20 = "LOG_API.DLL" nocase fullword ascii wide
        $dll21 = "LOG_API32.DLL" nocase fullword ascii wide
        $dll22 = "vmcheck32.dll" nocase ascii wide
        $dll23 = "vmcheck64.dll" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_AHK_Downloader {
    meta:
        description = "Detects AutoHotKey binaries acting as second stage droppers"
        author = "ditekSHen"
    strings:
        $d1 = "URLDownloadToFile, http" ascii
        $d2 = "URLDownloadToFile, file" ascii
        $s1 = ">AUTOHOTKEY SCRIPT<" fullword wide
        $s2 = "open \"%s\" alias AHK_PlayMe" fullword wide
        $s3 = /AHK\s(Keybd|Mouse)/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($d*) and 1 of ($s*))
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCOM {
    meta:
        description = "Detects Windows exceutables bypassing UAC using CMSTP COM interfaces. MITRE (T1218.003)"
        author = "ditekSHen"
    strings:
        // CMSTPLUA
        $guid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase
        // CMLUAUTIL
        $guid2 = "{3E000D72-A845-4CD9-BD83-80C07C3B881F}" ascii wide nocase
        // Connection Manager LUA Host Object
        $guid3 = "{BA126F01-2166-11D1-B1D0-00805FC1270E}" ascii wide nocase
        $s1 = "CoGetObject" fullword ascii wide
        $s2 = "Elevation:Administrator!new:" fullword ascii wide
    condition:
       uint16(0) == 0x5a4d and (1 of ($guid*) and 1 of ($s*))
}

rule INDICATOR_SUSPICIOUS_ClearWinLogs {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing commands for clearing Windows Event Logs"
    strings:
        $cmd1 = "wevtutil.exe clear-log" ascii wide nocase
        $cmd2 = "wevtutil.exe cl " ascii wide nocase
        $cmd3 = ".ClearEventLog()" ascii wide nocase
        $cmd4 = "Foreach-Object {wevtutil cl \"$_\"}" ascii wide nocase
        $cmd5 = "('wevtutil.exe el') DO (call :do_clear" ascii wide nocase
        $cmd6 = "| ForEach { Clear-EventLog $_.Log }" ascii wide nocase
        $cmd7 = "('wevtutil.exe el') DO wevtutil.exe cl \"%s\"" ascii wide nocase
        $t1 = "wevtutil" ascii wide nocase
        $l1 = "cl Application" ascii wide nocase
        $l2 = "cl System" ascii wide nocase
        $l3 = "cl Setup" ascii wide nocase
        $l4 = "cl Security" ascii wide nocase
        $l5 = "sl Security /e:false" ascii wide nocase
        $ne1 = "wevtutil.exe cl Aplicaci" fullword wide
        $ne2 = "wevtutil.exe cl Application /bu:C:\\admin\\backup\\al0306.evtx" fullword wide
        $ne3 = "wevtutil.exe cl Application /bu:C:\\admin\\backups\\al0306.evtx" fullword wide
    condition:
        uint16(0) == 0x5a4d and not any of ($ne*) and ((1 of ($cmd*)) or (1 of ($t*) and 4 of ($l*)))
}

rule INDICATOR_SUSPICIOUS_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing artifcats associated with disabling Widnows Defender"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $reg2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $s1 = "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" ascii wide nocase
        $s2 = "Set-MpPreference -DisableArchiveScanning $true" ascii wide nocase
        $s3 = "Set-MpPreference -DisableIntrusionPreventionSystem $true" ascii wide nocase
        $s4 = "Set-MpPreference -DisableScriptScanning $true" ascii wide nocase
        $s5 = "Set-MpPreference -SubmitSamplesConsent 2" ascii wide nocase
        $s6 = "Set-MpPreference -MAPSReporting 0" ascii wide nocase
        $s7 = "Set-MpPreference -HighThreatDefaultAction 6" ascii wide nocase
        $s8 = "Set-MpPreference -ModerateThreatDefaultAction 6" ascii wide nocase
        $s9 = "Set-MpPreference -LowThreatDefaultAction 6" ascii wide nocase
        $s10 = "Set-MpPreference -SevereThreatDefaultAction 6" ascii wide nocase
        $pdb = "\\Disable-Windows-Defender\\obj\\Debug\\Disable-Windows-Defender.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($reg*) and 1 of ($s*)) or ($pdb))
}

rule INDICATOR_SUSPICIOUS_USNDeleteJournal {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing anti-forensic artifcats of deletiing USN change journal. Observed in ransomware"
    strings:
        $cmd1 = "fsutil.exe" ascii wide nocase
        $s1 = "usn deletejournal /D C:" ascii wide nocase
        $s2 = "fsutil.exe usn deletejournal" ascii wide nocase
        $s3 = "fsutil usn deletejournal" ascii wide nocase
        $ne1 = "fsutil usn readdata C:\\Temp\\sample.txt" wide
        $ne2 = "fsutil transaction query {0f2d8905-6153-449a-8e03-7d3a38187ba1}" wide
        $ne3 = "fsutil resource start d:\\foobar d:\\foobar\\LogDir\\LogBLF::TxfLog d:\\foobar\\LogDir\\LogBLF::TmLog" wide
        $ne4 = "fsutil objectid query C:\\Temp\\sample.txt" wide
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and (1 of ($cmd*) and 1 of ($s*)))
}

rule INDICATOR_SUSPICIOUS_WMIC_Downloader {
    meta:
        author = "ditekSHen"
        description = "Detects files utilizing WMIC for whitelisting bypass and downloading second stage payloads"
    strings:
        $s1 = "WMIC.exe os get /format:\"http" wide
        $s2 = "WMIC.exe computersystem get /format:\"http" wide
        $s3 = "WMIC.exe dcomapp get /format:\"http" wide
        $s4 = "WMIC.exe desktop get /format:\"http" wide
    condition:
        (uint16(0) == 0x004c or uint16(0) == 0x5a4d) and 1 of them
}

rule INDICATOR_SUSPICIOUS_PE_ResourceTuner {
    meta:
        author = "ditekSHen"
        description = "Detects executables with modified PE resources usning the unpaid version of Resource Tuner"
    strings:
        $s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them 
}

rule INDICATOR_SUSPICIOUS_ASEP_REG_Reverse {
    meta:
        author = "ditekSHen"
        description = "Detects file containing reversed ASEP Autorun registry keys"
    strings:
        $s1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s2 = "ecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s3 = "secivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s4 = "xEecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s5 = "ecnOsecivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s6 = "yfitoN\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s7 = "tiniresU\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s8 = "nuR\\rerolpxE\\seiciloP\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s9 = "stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM" ascii wide nocase
        $s10 = "sLLD_tinIppA\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s11 = "snoitpO noitucexE eliF egamI\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s12 = "llehS\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s13 = "daol\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s14 = "daoLyaleDtcejbOecivreSllehS\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s15 = "nuRotuA\\rossecorP\\dnammoC\\tfosorciM" ascii wide nocase
        $s16 = "putratS\\sredloF llehS resU\\rerolpxE\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s17 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\teSlortnoCtnerruC\\metsyS" ascii wide nocase
        $s18 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\100teSlortnoC\\metsyS" ascii wide nocase
        $s19 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\erawtfoS" ascii wide nocase
        $s20 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\edoN2346woW\\erawtfoS" ascii wide nocase
    condition:
        1 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_SQLQuery_ConfidentialDataStore {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing SQL queries to confidential data stores. Observed in infostealers"
    strings:
        $select = "select " ascii wide nocase
        $table1 = " from credit_cards" ascii wide nocase
        $table2 = " from logins" ascii wide nocase
        $table3 = " from cookies" ascii wide nocase
        $table4 = " from moz_cookies" ascii wide nocase
        $column1 = "name" ascii wide nocase
        $column2 = "password_value" ascii wide nocase
        $column3 = "encrypted_value" ascii wide nocase
        $column4 = "card_number_encrypted" ascii wide nocase
        $column5 = "isHttpOnly" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 2 of ($table*) and 2 of ($column*) and $select
}

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"
    strings:
        $b1 = "::WriteAllBytes(" ascii
        $b2 = "::FromBase64String(" ascii
        $b3 = "::UTF8.GetString(" ascii

        $s1 = "-join" nocase ascii
        $s2 = "[Char]$_"
        $s3 = "reverse" nocase ascii
        $s4 = " += " ascii

        $e1 = "System.Diagnostics.Process" ascii
        $e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
        $e3 = /-eq\s'\.(exe|dll)'\)/ ascii
        $e4 = /(Get|Start)-(Process|WmiObject)/ ascii
    condition:
        #s4 > 10 and ((3 of ($b*)) or (1 of ($b*) and 2 of ($s*) and 1 of ($e*)) or (8 of them))
}

rule INDICATOR_SUSPICIOUS_JS_Hex_B64Encoded_EXE {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files hex and base64 encoded executables"
    strings:
        $s1 = ".SaveToFile" ascii
        $s2 = ".Run" ascii
        $s3 = "ActiveXObject" ascii
        $s4 = "fromCharCode" ascii
        $s5 = "\\x66\\x72\\x6F\\x6D\\x43\\x68\\x61\\x72\\x43\\x6F\\x64\\x65" ascii
        $binary = "\\x54\\x56\\x71\\x51\\x41\\x41" ascii
        $pattern = /[\s\{\(\[=]_0x[0-9a-z]{3,6}/ ascii
    condition:
        $binary and $pattern and 2 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_EXE_PWSH_Downloader {
    meta:
        author = "ditekSHen"
        description = "Detects downloader agent, using PowerShell"
    strings:
        $pwsh = "powershell" fullword ascii
        $bitstansfer = "Start-BitsTransfer" ascii wide
        $s1 = "GET %s HTTP/1" ascii
        $s2 = "User-Agent:" ascii
        $s3 = "-WindowStyle Hidden -ep bypass -file \"" fullword ascii
        $s4 = "LdrLoadDll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and $pwsh and ($bitstansfer or 2 of ($s*))
}

rule INDICATOR_SUSPICIOUS_PWSH_PasswordCredential_RetrievePassword {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell content designed to retrieve passwords from host"
    strings:
        $namespace = "Windows.Security.Credentials.PasswordVault" ascii wide nocase
        $method1 = "RetrieveAll()" ascii wide nocase
        $method2 = ".RetrievePassword()" ascii wide nocase
    condition:
       $namespace and 1 of ($method*)
}

rule INDICATOR_SUSPICIOUS_UACBypass_EnvVarScheduledTasks {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC (ab)using Environment Variables in Scheduled Tasks"
    strings:
        $s1 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii wide
        $s2 = "\\Environment" ascii wide
        $s3 = "schtasks" ascii wide
        $s4 = "/v windir" ascii wide
    condition:
       all of them
}

rule INDICATOR_SUSPICIOUS_UACBypass_fodhelper {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = "\\software\\classes\\ms-settings\\shell\\open\\command" ascii wide nocase
        $s2 = "DelegateExecute" ascii wide
        $s3 = "fodhelper" ascii wide
        $s4 = "ConsentPromptBehaviorAdmin" ascii wide
    condition:
       all of them
}

rule INDICATOR_SUSPICIOUS_Win_GENERIC01 {
    meta:
        author = "ditekSHen"
        description = "Detects known unamed malicious executables, mostly DLLs"
    strings:
        $s1 = "xcopy \"%s\" \"%s\" /e /i /y" fullword ascii
        $s2 = "LoadFromMemory END---" fullword ascii
        $s3 = "<<== Message sending:" fullword ascii
        $s4 = "==>> Message received:" fullword ascii
        $s5 = "I am virus! Fuck you" ascii
        $s6 = "TMBMSRV.exe" fullword ascii
        $s7 = "rtvscan.exe" fullword ascii
        $s8 = "SPIDer.exe" fullword ascii
        $s9 = "kxetray.exe" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_SUSPICIOUS_Win_GENERIC02 {
    meta:
        author = "ditekSHen"
        description = "Detects known unamed malicious executables, mostly DLLs"
    strings:
        $s1 = "\\wmkawe_%d.data" ascii
        $s2 = "\\resmon.resmoncfg" ascii
        $s3 = "ByPassUAC" fullword ascii
        $s4 = "rundll32.exe C:\\ProgramData\\Sandboxie\\SbieMsg.dll,installsvc" fullword ascii nocase
        $s5 = "%s\\SbieMsg." ascii
        $s6 = "Stupid Japanese" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_SUSPICIOUS_Win_GENERIC03 {
    meta:
        author = "ditekSHen"
        description = "Detects known unamed malicious executables"
    strings:
        $s1 = "{%s-%d-%d}" fullword wide
        $s2 = "update" fullword wide
        $s3 = "https://" fullword wide
        $s4 = "http://" fullword wide
        $s5 = "configure" fullword ascii
        $s6 = { 8d 4f 02 e8 8c ff ff ff 8b d8 81 fb 00 dc 00 00 }
        $s7 = { 83 c1 02 e8 3c ff ff ff 8b c8 ba ff 03 00 00 8d }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_Finger_Download_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects files embedding and abusing the finger command for download"
    strings:
        $pat1 = /finger(\.exe)?\s.{1,50}@.{7,}\|/ ascii wide
        $pat2 = "-Command \"finger" ascii wide
        $ne1 = "Nmap service detection probe list" ascii
    condition:
       not any of ($ne*) and any of ($pat*)
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCMD {
    meta:
        author = "ditekSHen"
        description = "Detects Windows exceutables bypassing UAC using CMSTP utility, command line and INF"
    strings:
        $s1 = "c:\\windows\\system32\\cmstp.exe" ascii wide nocase
        $s2 = "taskkill /IM cmstp.exe /F" ascii wide nocase
        $s3 = "CMSTPBypass" fullword ascii
        $s4 = "CommandToExecute" fullword ascii
        $s5 = "RunPreSetupCommands=RunPreSetupCommandsSection" fullword wide
        $s6 = "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"" fullword wide nocase
    condition:
       uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_JS_WMI_ExecQuery {
    meta:
        author = "ditekSHen"
        description = "Detects JS potentially executing WMI queries"
    strings:
        $ex = ".ExecQuery(" ascii nocase
        $s1 = "GetObject(" ascii nocase
        $s2 = "String.fromCharCode(" ascii nocase
        $s3 = "ActiveXObject(" ascii nocase
        $s4 = ".Sleep(" ascii nocase
    condition:
       ($ex and 2 of ($s*))
}

rule INDICATOR_SUSPICIOUS_PWSHLoader_RunPE {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell PE loader / executer. Observed MasterMana TTPs"
    strings:
        $rp1 = "GetType('RunPe.RunPe'" ascii
        $rp2 = "GetType(\"RunPe.RunPe\"" ascii
        $rm1 = "GetMethod('Run'" ascii
        $rm2 = "GetMethod(\"Run\"" ascii
        $s1 = ".Invoke(" ascii
        $s2 = "[Reflection.Assembly]::Load(" ascii
    condition:
        all of ($s*) and 1 of ($rp*) and 1 of ($rm*)
}

rule INDICATOR_SUSPICIOUS_PELoader_RunPE {
    meta:
        author = "ditekSHen"
        description = "Detects PE loader / injector. Observed Gorgon TTPs"
    strings:
        $s1 = "commandLine'" fullword ascii
        $s2 = "RunPe.dll" fullword ascii
        $s3 = "HandleRun" fullword ascii
        $s4 = "inheritHandles" fullword ascii
        $s5 = "BlockCopy" fullword ascii
        $s6 = "WriteProcessMemory" fullword ascii
        $s7 = "startupInfo" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 6 of them
}
