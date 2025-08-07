rule MonsterV2
{
    meta:
        author = "YungBinary"
        description = "MonsterV2/Aurotun Payload"
        cape_type = "MonsterV2 Payload"
        packed = "fe69e8db634319815270aa0e55fe4b9c62ce8e62484609c3a42904fbe5bb2ab3"
    strings:
        $decrypt_config = {
            41 B8 0E 04 00 00
            48 8D 15 ?? ?? ?? 00
            48 8B CB
            E8 ?? ?? ?? ??
            48 8D 83 0E 04 00 00
            48 89 44 24 30
            48 89 6C 24 70
            4C 8B C7
            48 8D 54 24 28
            48 8B CE
            E8 ?? ?? ?? ??
        }
    condition:
        $decrypt_config
}
