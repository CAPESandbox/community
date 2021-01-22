rule CoreBot {
    meta:
        author = "ditekSHen"
        description = "Detects CoreBot"
        cape_type = "CoreBot Payload"
    strings:
        $f1 = "core.cert_fp" fullword ascii
        $f2 = "core.crash_handler" fullword ascii
        $f3 = "core.delay" fullword ascii
        $f4 = "core.guid" fullword ascii
        $f5 = "core.inject" fullword ascii
        $f6 = "core.installed_file" fullword ascii
        $f7 = "core.plugins_dir" fullword ascii
        $f8 = "core.plugins_key" fullword ascii
        $f9 = "core.safe_mode" fullword ascii
        $f10 = "core.server" fullword ascii
        $f11 = "core.servers" fullword ascii
        $f12 = "core.test_env" fullword ascii
        $f13 = "core.vm_detect" fullword ascii
        $f14 = "core.vm_detect_skip" fullword ascii
        $s1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko" fullword wide
        $s2 = "\\Microsoft\\Windows\\AppCache" wide
        $s3 = "crash_flag" fullword wide
        $s4 = "container.dat" fullword wide
        $s5 = "INJECTED" fullword ascii
        $s6 = "tmp.delete_file" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($f*) or all of ($s*) or (3 of ($s*) and 2 of ($f*)))
}
