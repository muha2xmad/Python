rule amadey_bot {
    meta:
        description = "Detects Amadey malware"
        author = "muha2xmad"
        date = "2023-08-14"
        hash1 = "5effd65eee9e31b8a5a133284face14095903d157202465ed885aa19a0dffa4e"
        hash2 = "6cc5aeeb3a586cc0ff7d3a4fc136f13ab5b44ece219ef63c77946922fb5c342b"
        hash3 = "7560bd490edfc33c287b53201060257e3625c6f8fdd6f6cea157309a4186e3ec"
        hash4 = "2a72b302004c17baf6d69fa1c0559d2e10009643fd06bfeb29f0ab3edc531f23"
    strings:

        $str_constructor = {68 ?? ?? ?? 00 b9 ?? ?? 44 00 e8 ?? ?? 01 00 68 ?? ?? 43 00 e8 ?? ?? 01 00}

        // .text:00401CA2 68 0C 7F 44 00                          push    offset a0mgbqzdlkr ; "0mgbQZdLKr=="
        // .text:00401CA7 B9 94 C3 44 00                          mov     ecx, offset dword_44C394 ; void *
        // .text:00401CAC E8 AF 46 01 00                          call    mw_str_constructor
        // .text:00401CB1 68 40 94 43 00                          push    offset sub_439440 ; void (__cdecl *)()
        // .text:00401CB6 E8 33 71 01 00                          call    _atexit
        
        
        
        $str1 = "\\v\\v\\n\\n\\t\\t\\t\\t\\t\\b\\b\\b\\b\\b\\b\\b\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a\\a"
        $str2 = "xpxxxx\\b\\a\\b\\a"
        $str3 = "D:\\Mktmp\\"
        $str4 = "operator \"\" "
        $str5 = ".?AVtype_info@@"
    condition:
        uint16(0) == 0x5a4d and ( 2 of ($str*) ) and $str_constructor
}
