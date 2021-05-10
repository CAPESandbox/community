rule Darkside
{
    meta:
        author = "Rony (@r0ny_123)"
        description = "Detects Darkside ransomware"
        date = "2021-05-10"
        cape_type = "Darkside Ransomware Payload"
        TLP = "GREEN"
    strings:
        $op = {8b ec 51 52 53 56 57 e8 [4] b9 [4] f7 e1 05 [4] 25 [4] 8b 4d ?? 33 d2 f7 f1 92 5f 5e 5b 5a 59}
    condition:
        $op
}