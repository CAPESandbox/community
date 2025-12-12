rule ShanyaPacker {
    meta:
        author = "Abdallah Elshinbary (n1ghtw0lf), Threatray"
        description = "Hunting rule for Shanya packer"
        license = "Detection Rule License (DRL) 1.1"
        date = "2025-12-11"
        hash1 = "6645297a0a423564f99b9f474b0df234d6613d04df48a94cb67f541b8eb829d1"
        hash2 = "e8bf060de32a342a7a79d89e98428d80084777ac39d7ef017607af1582c4c9d3"

    strings:
        $api_hash_v1a = {
            46                    // inc     esi
            8A 1E                 // mov     bl, [esi]
            0F BE D3              // movsx   edx, bl
            8B CA                 // mov     ecx, edx
            83 C9 20              // or      ecx, 20h
            8D 43 BF              // lea     eax, [ebx-41h]
            3C 19                 // cmp     al, 19h
            0F 47 CA              // cmova   ecx, edx
            03 CF                 // add     ecx, edi
            69 F9 [4]             // imul    edi, ecx, 0A38C8EEEh
            84 DB                 // test    bl, bl
            75                    // jnz     short loc_10177DAA
        }
        $api_hash_v1b = {
            48 8D 49 02            // lea     rcx, [rcx+2]
            0F B7 11               // movzx   edx, word ptr [rcx]
            8D 42 BF               // lea     eax, [rdx-41h]
            66 83 F8 19            // cmp     ax, 19h
            8B C2                  // mov     eax, edx
            77 ??                  // ja      short loc_14020B8BA
            83 C8 20               // or      eax, 20h
            41 03 C0               // add     eax, r8d
            44 69 C0 [4]           // imul    r8d, eax, 434BAACDh
            66 85 D2               // test    dx, dx
            75                     // jnz     short loc_14020B8A5
        }
        $api_hash_v2 = {
            80 F9 41                // cmp     cl, 41h ; 'A'
            7C ??                   // jl      short loc_1801761E8
            3C 5A                   // cmp     al, 5Ah ; 'Z'
            7F ??                   // jg      short loc_1801761E8
            0F BE C8                // movsx   ecx, al
            83 C9 20                // or      ecx, 20h
            EB ??                   // jmp     short loc_1801761EB
            0F BE C8                // movsx   ecx, al
            81 C1 [4]               // add     ecx, 1835B892h
            45 6B C0 1F             // imul    r8d, 1Fh
            48 FF C2                // inc     rdx
            8A 02                   // mov     al, [rdx]
            44 33 C1                // xor     r8d, ecx
            8A C8                   // mov     cl, al
            84 C0                   // test    al, al
            75                      // jnz     short loc_1801761D7
        }

    condition:
        any of them
}
