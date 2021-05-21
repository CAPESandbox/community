rule CoinMiner01 {
    meta:
        author = "ditekSHen"
        description = "Detects coinminer payload"
        cape_type = "CoinMiner Payload"
    strings:
        $s1 = "-o pool." ascii wide
        $s2 = "--cpu-max-threads-hint" ascii wide
        $s3 = "-P stratum" ascii wide
        $s4 = "--farm-retries" ascii wide
        $dl = "github.com/ethereum-mining/ethminer/releases/download" ascii wide
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) or ($dl))
}
