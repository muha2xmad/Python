rule stealc_stealer {
    meta:
        description = "Detects Stealc malware"
        author = "muha2xmad"
        date = "2023-08-11"
        hash1 = "0873b7a5cfae17a6dfebe6afde535a186b08d76b4b8ef56a129459c56f016729"
        hash2 = "cc4ce27b042213058ffb13a5078b681dc99e516fb2861b8b3637a25681fd15ec"
        hash2 = "a398e940847ee51fa7fed05b1c6b38a47c1668c14616a0f39f56fd314fe92ad8"
    
    strings:
        $rc4_key = {C7 05 84 82 61 00 54 4D 41 00}
        // mov     dword_618284, offset a81068331301379 ; "8106833130137977202684225"
        $decryption_routine = {68 ?? ?? 41 00 E8 ?? ?? 00 00 83 c4 04 A3 ?? ?? 61 00}
        // 68 B4 4E 41 00      push    offset aXdw     ; "XDw="
        // E8 E9 1A 00 00      call    sub_403E80
        // 83 C4 04            add     esp, 4
        // A3 08 85 61 00      mov     dword_618508, eax

        $str1 = "------" fullword wide
        $str2 = "\\a\\b\\t\\n\\v" fullword 
        $str3 = "@@@@@@" fullword wide
        $str4 = "%s\\%s\\%s" fullword wide
        $str5 = "\"\r\n\r\n" fullword wide
        $str6 = "VirtualFree" fullword ascii
        $str7 = "strtok_s" fullword ascii

    condition:
        uint16(0) == 0x5a4d and ( 2 of ($str*) ) and $rc4_key and $decryption_routine
}
