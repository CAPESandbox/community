rule Lu0Bot 
{
    meta:
        author = "ditekSHen, @Fmk0, @r0ny123"
        description = "Detects Lu0Bot"
        cape_type = "Lu0Bot Payload"
        modified_date = "2021-12-14"
    strings:
        /*
        be 00 20 40 00       mov        esi, 0x402000
        89 f7                mov        edi, esi
        31 c0                xor        eax, eax
        89 f0                mov        eax, esi
        81 c7 cc 01 00 00    add        edi, 0x1cc
        81 2e 4b 4b 4d 4c    sub        dword ptr [esi], 0x4c4d4b4b
        83 c6 04             add        esi, 4
        39 fe                cmp        esi, edi
        7c f3                jl         0x40110e
        bb 00 00 00 00       mov        ebx, 0
        53                   push       ebx
        */
        $s = { be [4] 89 f7 [0-2] 89 f0 81 c7 [4] 81 2e [4] 83 c6 ?? 39 fe 7c ?? bb [4] 53 }
    condition:
        uint16be(0) == 0x4D5A and uint32be(uint32(0x3C)) == 0x50450000 and filesize < 5KB and all of them
}
