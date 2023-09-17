rule PovertyStealer_rule {
    meta:
        description = "Detects PovertyStealer malware"
        author = "Muhammad Hasan Ali @muha2xmad"
        date = "2023-09-17"
    strings:
        $str001 = "$d.log" fullword ascii wide
        $str002 = "Poverty is the parent of crime." fullword ascii wide
        $str003 = "- HWID: %s\\r\\n" fullword ascii wide
        $str004 = "- CPU: %s (%d cores)\\r\\n" fullword ascii wide
        $str005 = "- VideoAdapter #%d: %s\\r\\n" fullword ascii wide
        $str006 = "- OperationSystem: %d:%d:%d\\r\\n" fullword ascii wide
        $str007 = "- ScreenSize: {lWidth=%d, lHeight=%d}\\r\\n" fullword ascii wide
        $str008 = "- SystemLayout %d\\r\\n" fullword ascii wide
        $str009 = "- KeyboardLayouts: ( " fullword ascii wide

        $func01 = {66 B9 ?? ?? E8 F4 FE FF FF}

        // .text:004050F9 66 B9 B3 08                             mov     cx, 2227
        // .text:004050FD E8 F4 FE FF FF                          call    swap_func
        


    condition:
        uint16(0) == 0x5a4d and (3 of ($str00*)) and $func01
}
