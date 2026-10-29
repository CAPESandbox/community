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

rule shellcode_peb_parsing
{
    meta:
        author = "William Ballenthin"
        email = "william.ballenthin@fireeye.com"
        license = "Apache 2.0"
        copyright = "FireEye, Inc"
        description = "Match x86 that appears to manually traverse the TEB/PEB/LDR data."

    strings:
       //                                                         ;; TEB->PEB
       // (64 a1 30 00 00 00 |                                    ; mov eax, fs:30
       //  64 8b (1d | 0d | 15 | 35 | 3d) 30 00 00 00 |           ; mov $reg, DWORD PTR fs:0x30
       //  31 (c0 | db | c9 | d2 | f6 | ff) [0-8] 64 8b ?? 30 )   ; xor $reg; mov $reg, DWORD PTR fs:[$reg+0x30]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; PEB->LDR_DATA
       // 8b ?? 0c                                                ; mov eax,DWORD PTR [eax+0xc]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; LDR_DATA->OrderLinks
       // 8b ?? (0c | 14 | 1C)                                    ; mov edx, [edx+0Ch]
       // [0-8]                                                   ; up to 8 bytes of interspersed instructions
       //                                                         ;; _LDR_DATA_TABLE_ENTRY.DllName.Buffer
       // 8b ?? (28 | 30)                                         ; mov esi, [edx+28h]
       $peb_parsing = { (64 a1 30 00 00 00 | 64 8b (1d | 0d | 15 | 35 | 3d) 30 00 00 00 | 31 (c0 | db | c9 | d2 | f6 | ff) [0-8] 64 8b ?? 30 ) [0-8] 8b ?? 0c [0-8] 8b ?? (0c | 14 | 1C) [0-8] 8b ?? (28 | 30) }

       $peb_parsing64 = { (48 65 A1 60 00 00 00 00 00 00 00 | 65 (48 | 4C) 8B ?? 60 00 00 00 | 65 A1 60 00 00 00 00 00 00 00 | 65 8b ?? ?? 00 FF FF | (48 31 (c0 | db | c9 | d2 | f6 | ff) | 4D 31 (c0 | c9))  [0-16] 65 (48 | 4d | 49 | 4c) 8b ?? 60) [0-16] (48 | 49 | 4C) 8B ?? 18 [0-16] (48 | 49 | 4C) 8B ?? (10 | 20 | 30) [0-16] (48 | 49 | 4C) 8B ?? (50 | 60) }

    condition:
       $peb_parsing or $peb_parsing64
}

rule shellcode_stack_strings
{
    meta:
        author = "William Ballenthin"
        email = "william.ballenthin@fireeye.com"
        license = "Apache 2.0"
        copyright = "FireEye, Inc"
        description = "Match x86 that appears to be stack string creation."

    strings:
        // stack string near the frame pointer.
        // the compiler may choose to use a single byte offset from $bp.
        // like: mov [ebp-10h], 25h
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_small_bp = /(\xC6\x45.[a-zA-Z0-9 -~]){4,}\xC6\x45.\x00/

        // dword stack string near the frame pointer.
        // the compiler may choose to use a single byte offset from $bp.
        // it may move four bytes at a time onto the stack.
        // like: mov [ebp-10h], 680073h  ; "sh"
        //
        // regex explanation:
        //   2 times:
        //     byte C7          (mov dword)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     printable ascii  (the immediate constant)
        //     byte 00          (second byte of utf-16 encoding of ascii character)
        //     printable ascii  (the immediate constant)
        //     byte 00          (second byte of utf-16 encoding of ascii character)
        //   1 times:
        //     byte C7          (mov dword)
        //     byte 45          ($bp-relative, one-byte offset)
        //     any byte         (the offset from $bp)
        //     any byte         (immediate constant or NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        //     byte 00          (the immediate constant, NULL terminator)
        $ss_small_bp_dword = /(\xC7\x45.[a-zA-Z0-9 -~]\x00[a-zA-Z0-9 -~]\x00){2,}\xC7\x45..\x00\x00\x00/

        // stack strings further away from the frame pointer.
        // the compiler may choose to use a four-byte offset from $bp.
        // like: mov byte ptr [ebp-D80h], 5Ch
        // we restrict the offset to be within 0xFFF (4095) of the frame pointer.
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 85          ($bp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $bp)
        //     byte 0xF0-0xFF   (second LSB of the offset from $bp)
        //     byte FF          (second MSB)
        //     byte FF          (MSB of the offset from $bp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 85          ($bp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $bp)
        //     byte 0xF0-0xFF   (second LSB of the offset from $bp)
        //     byte FF          (second MSB)
        //     byte FF          (MSB of the offset from $bp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_big_bp = /(\xC6\x85.[\xF0-\xFF]\xFF\xFF[a-zA-Z0-9 -~]){4,}\xC6\x85.[\xF0-\xFF]\xFF\xFF\x00/

        // stack string near the stack pointer.
        // the compiler may choose to use a single byte offset from $sp.
        // like: mov byte ptr [esp+0Bh], 24h
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 44          ($sp-relative, one-byte offset)
        //     byte 24          ($sp-relative, one-byte offset)
        //     any byte         (the offset from $sp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 44          ($sp-relative, one-byte offset)
        //     byte 24          ($sp-relative, one-byte offset)
        //     any byte         (the offset from $sp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_small_sp = /(\xC6\x44\x24.[a-zA-Z0-9 -~]){4,}\xC6\x44\x24.\x00/

        // stack strings further away from the stack pointer.
        // the compiler may choose to use a four-byte offset from $sp.
        // like: byte ptr [esp+0DDh], 49h
        // we restrict the offset to be within 0xFFF (4095) of the stack pointer.
        //
        // regex explanation:
        //   4 times:
        //     byte C6          (mov byte)
        //     byte 84          ($sp-relative, four-byte offset)
        //     byte 24          ($sp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $sp)
        //     byte 0x00-0x0F   (second LSB of the offset from $sp)
        //     byte 00          (second MSB)
        //     byte 00          (MSB of the offset from $sp)
        //     printable ascii  (the immediate constant)
        //   1 times:
        //     byte C6          (mov byte)
        //     byte 84          ($sp-relative, four-byte offset)
        //     byte 24          ($sp-relative, four-byte offset)
        //     any byte         (LSB of the offset from $sp)
        //     byte 0x00-0x0F   (second LSB of the offset from $sp)
        //     byte 00          (second MSB)
        //     byte 00          (MSB of the offset from $sp)
        //     byte 00          (the immediate constant, null terminator)
        $ss_big_sp = /(\xC6\x84\x24.[\x00-\x0F]\x00\x00[a-zA-Z0-9 -~]){4,}\xC6\x84\x24.[\x00-\x0F]\x00\x00\x00/

    condition:
        $ss_small_bp or $ss_small_bp_dword or $ss_big_bp or $ss_small_sp or $ss_big_sp
}

rule shellcode_shikataganai_encoding
{
    meta:
        author    = "Steven Miller"
        company   = "FireEye"
        reference = "https://www.fireeye.com/blog/threat-research/2019/10/shikata-ga-nai-encoder-still-going-strong.html"
    strings:
        $varInitializeAndXorCondition1_XorEAX = { B8 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
        $varInitializeAndXorCondition1_XorEBP = { BD ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
        $varInitializeAndXorCondition1_XorEBX = { BB ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
        $varInitializeAndXorCondition1_XorECX = { B9 ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
        $varInitializeAndXorCondition1_XorEDI = { BF ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
        $varInitializeAndXorCondition1_XorEDX = { BA ?? ?? ?? ?? [0-30] D9 74 24 F4 [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }
        $varInitializeAndXorCondition2_XorEAX = { D9 74 24 F4 [0-30] B8 ?? ?? ?? ?? [0-10] ( 59 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 40 | 41 | 42 | 43 | 45 | 46 | 47 ) ?? }
        $varInitializeAndXorCondition2_XorEBP = { D9 74 24 F4 [0-30] BD ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5B | 5C | 5E | 5F ) [0-50] 31 ( 68 | 69 | 6A | 6B | 6D | 6E | 6F ) ?? }
        $varInitializeAndXorCondition2_XorEBX = { D9 74 24 F4 [0-30] BB ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5C | 5D | 5E | 5F ) [0-50] 31 ( 58 | 59 | 5A | 5B | 5D | 5E | 5F ) ?? }
        $varInitializeAndXorCondition2_XorECX = { D9 74 24 F4 [0-30] B9 ?? ?? ?? ?? [0-10] ( 58 | 5A | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 48 | 49 | 4A | 4B | 4D | 4E | 4F ) ?? }
        $varInitializeAndXorCondition2_XorEDI = { D9 74 24 F4 [0-30] BF ?? ?? ?? ?? [0-10] ( 58 | 59 | 5A | 5B | 5C | 5D | 5E ) [0-50] 31 ( 78 | 79 | 7A | 7B | 7D | 7E | 7F ) ?? }
        $varInitializeAndXorCondition2_XorEDX = { D9 74 24 F4 [0-30] BA ?? ?? ?? ?? [0-10] ( 58 | 59 | 5B | 5C | 5D | 5E | 5F ) [0-50] 31 ( 50 | 51 | 52 | 53 | 55 | 56 | 57 ) ?? }
    condition:
        any of them
}

rule Shellcode_PEB_Walk_x86 {
    meta:
        description = "Detects possible 32-bit PEB walking and Export Directory resolution"
        reference = "https://moval0x1.github.io/posts/the-peb-walk-anatomy/"

    strings:
        $peb_1 = { 64 A1 30 00 00 00 }
        $peb_2 = { 64 8B ?? 30 }
        $peb_3 = { 64 8B ?? ?? 30 }
        $peb_4 = { 64 8B ?? 30 00 00 00 }
        $peb_5 = { 64 FF 35 30 00 00 00 }
        $peb_6 = { 6A 30 [0-4] 5? [0-4] 64 8B }
        $peb_7 = { 64 A1 18 00 00 00 [0-16] 8B ?? 30 }
        $peb_8 = { 64 8B ?? 18 [0-16] 8B ?? 30 }

        $ldr_chain = { 8B ( 4? | 5? | 6? | 7? ) 0C [0-48] ( 8B | 8D ) [1-2] ( 0C | 14 | 1C ) }
        $ldr_base_name = { 8B ( 4? | 5? | 6? | 7? ) ( 18 | 20 | 28 ) [0-32] ( 8B | 8D ) [1-2] ( 24 | 2C | 30 ) }
        $eat_lookup = { 8B ( 4? | 5? | 6? | 7? ) 3C [0-32] 8B [1-3] 78 [0-32] 8B [1-2] ( 18 | 1C | 20 | 24 ) }

    condition:
        for any of ($peb_*) : (
            $ldr_chain in (@ .. @ + 64) and (
                $ldr_base_name in (@ .. @ + 160) or
                $eat_lookup in (@ - 220 .. @ + 220)
            )
        )
}

rule Shellcode_PEB_Walk_x64 {
    meta:
        description = "Detects possible 64-bit PEB walking and Export Directory resolution"
        reference = "https://moval0x1.github.io/posts/the-peb-walk-anatomy/"

    strings:
        $peb64_1 = { 65 ( 48 | 4C ) 8B ?? 25 60 00 00 00 }
        $peb64_2 = { 65 ( 48 | 4C ) 8B ?? 60 }
        $peb64_3 = { 65 ( 48 | 4C ) 8B 04 ?? 60 00 00 00 }
        $peb64_4 = { 6A 60 [0-4] ( 5? | 41 5? ) [0-4] 65 ( 48 | 4C ) 8B }
        $peb64_5 = { 65 ( 48 | 4C ) 8B ?? 25 30 00 00 00 [0-16] ( 48 | 4C ) 8B ?? 60 }
        $peb64_6 = { 65 ( 48 | 4C ) 8B ?? 30 [0-16] ( 48 | 4C ) 8B ?? 60 }

        $ldr64_chain = { ( 48 | 4C ) 8B ( 4? | 5? | 6? | 7? ) 18 [0-48] ( 48 | 4C ) ( 8B | 8D ) [1-2] ( 10 | 20 | 30 ) }
        $ldr64_base_name = { ( 48 | 4C ) 8B ( 4? | 5? | 6? | 7? ) ( 30 | 48 | 50 | 58 | 60 ) [0-36] ( 48 | 4C | 66 ) ( 8B | 8D ) [1-2] ( 30 | 48 | 50 | 58 | 60 ) }
        $eat64_lookup = { ( 8B | 41 8B | 44 8B | 45 8B ) [1-2] 3C [0-48] 8B ?? ?? 88 00 00 00 }
        $eat64_lookup_sib = { ( 8B | 41 8B | 44 8B | 45 8B ) [1-2] 3C [0-48] 8B ?? 88 00 00 00 }

    condition:
        for any of ($peb64_*) : (
            $ldr64_chain in (@ .. @ + 64) and (
                $ldr64_base_name in (@ .. @ + 160) or
                $eat64_lookup in (@ - 220 .. @ + 220) or
                $eat64_lookup_sib in (@ - 220 .. @ + 220)
            )
        )
}
