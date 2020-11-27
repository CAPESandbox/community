rule Ficker {
    meta:
        author = "ditekSHen"
        description = "Ficker infosteaker payload"
        cape_type = "Ficker Payload"
    strings:
        $s1 = ":EDIJNOde\\" ascii
        $s2 = "\"SomeNone" fullword ascii
        $s3 = "kindmessage" fullword ascii
        $s4 = "..\\\\?\\.\\UNC\\Windows stdio in console mode does not support writting non-UTF-8 byte sequences" ascii
        $s5 = "(os error other os erroroperation interrruptedwrite zerotimed)" ascii
        $s6 = "_matherr(): %s in %s(%g, %g)  (retval=%g)" ascii
    condition:
        uint32(0) == 0x5a4d and all of them
}
