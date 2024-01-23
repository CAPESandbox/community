rule shellcode_patterns
{
    meta:
        author = "nex"
        description = "Matched shellcode byte patterns"

    strings:
        $mz = { 4d 5a }
        $shell1 = { 64 8b 64 }
        $shell2 = { 64 a1 30 }
        $shell3 = { 64 8b 15 30 }
        $shell4 = { 64 8b 35 30 }
        $shell5 = { 55 8b ec 83 c4 }
        $shell6 = { 55 8b ec 81 ec }
        $shell7 = { 55 8b ec e8 }
        $shell8 = { 55 8b ec e9 }
    condition:
        not ($mz at 0) and
        any of ($shell*)
}

rule shellcode_get_eip
{
    meta:
        author = "William Ballenthin"
        email = "william.ballenthin@fireeye.com"
        license = "Apache 2.0"
        copyright = "FireEye, Inc"
        description = "Match x86 that appears to fetch $PC."

    strings:
       // 0:  e8 00 00 00 00          call   5 <_main+0x5>
       // 5:  58                      pop    eax
       // 6:  5b                      pop    ebx
       // 7:  59                      pop    ecx
       // 8:  5a                      pop    edx
       // 9:  5e                      pop    esi
       // a:  5f                      pop    edi
       $x86 = { e8 00 00 00 00 (58 | 5b | 59 | 5a | 5e | 5f) }

    condition:
       $x86
}
