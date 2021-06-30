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

rule CoinMiner02 {
    meta:
        author = "ditekSHen"
        description = "Detects coinmining malware"
        cape_type = "CoinMiner Payload"
    strings:
        $s1 = "%s/%s (Windows NT %lu.%lu" fullword ascii
        $s2 = "\\Microsoft\\Libs\\WR64.sys" wide
        $s3 = "\\\\.\\WinRing0_" wide
        $s4 = "pool_wallet" ascii
        $s5 = "cryptonight" ascii
        $s6 = "mining.submit" ascii
        $c1 = "stratum+ssl://" ascii
        $c2 = "daemon+http://" ascii
        $c3 = "stratum+tcp://" ascii
        $c4 = "socks5://" ascii
        $c5 = "losedaemon+https://" ascii
    condition:
        uint16(0) == 0x5a4d and (3 of ($s*) and 1 of ($c*))
}
