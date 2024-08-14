rule Grum {
    meta:
      author = "ditekSHen"
      description = "Detect Grum spam bot"
      cape_type = "Grum Payload"
    strings:
        $s1 = "loader_id" fullword ascii
        $s2 = "start_srv" fullword ascii
        $s3 = "lid_file_upd" fullword ascii
        $s4 = "----=_NextPart_%03d_%04X_%08.8lX.%08.8lX" fullword ascii
        $s5 = "rcpt to:<%s>" fullword ascii
        $s6 = "ehlo %s" fullword ascii
        $s7 = "%OUTLOOK_BND_" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 5 of them) or (all of them)
}
