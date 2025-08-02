// https://www.esentire.com/blog/unpacking-shadowcoils-ransomhub-ex-affiliate-credential-harvesting-tool
// https://github.com/eSentire/iocs/blob/main/ShadowCoil/shadowcoil_unpacker.py

rule ShadowCoil_Packed_Python
{
    meta:
        author = "YungBinary"
        description = "Detects packed/python RansomHub ex-affiliate tools"
        target_entity = "file"
        cape_type = "ShadowCoil Payload"
    strings:
        $a = "exec(pc_start(" ascii
        $b = "get_hw_key():" ascii
        $c = "'vm', 'virtual'" ascii
        $d = "TracerPid:" ascii
    condition:
        all of them
}
