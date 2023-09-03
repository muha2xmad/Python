rule DCRat {
    meta:
        author = "Muammad Hasan Ali @muha2xmad"
        date = "2023-09-03"
        description = "YARA rule for DCRat indicators"
    strings:
        $str001 = "cao28Fn172GnuaZvuO_OnSystemInfoO29PluginI2bG7" fullword wide
        $str002 = "uploadsafefile_name" fullword wide
        $str003 = "uploadfile_name" fullword wide
        $str004 = "searchpath" fullword wide
        $str005 = "runas" fullword wide
        $str006 = "@@EXTRACTLOCATION" fullword wide
        $str007 = "@@EXTRACT_EXISTING_FILE" fullword wide
        $str008 = "@@POST_UNPACK_CMD_LINE" fullword wide
        $str009 = "@@REMOVE_AFTER_EXECUTE" fullword wide
        $str010 = "ACTWindow" fullword wide
        $str011 = "Clipboard [Files].txt" fullword wide
        $str012 = "Clipboard [Text].txt" fullword wide
        $str013 = "ConfigPluginName" fullword wide
        $str014 = "saving...." fullword wide
        $str015 = "DCRat-Log#" fullword wide
        $str016 = "DCRat.Code" fullword wide
        $str017 = "EncTable" fullword wide
        $str018 = "OldPath" fullword wide
        $str019 = "[Clipboard] Saving information..." fullword wide
        $str020 = "[Plugin] Invoke:" fullword wide
        $str021 = "[Screenshot] Saving screenshots from" fullword wide
        $str022 = "[SystemInfromation] Saving information..." fullword wide
        $str023 = "stealerlogstatus" fullword wide

        $API01 = "UseShellExecute" fullword ascii wide
        $API02 = "FromBase64String" fullword ascii wide
        $API03 = "GZipStream" fullword ascii wide
        $API04 = "GetTempPath" fullword ascii wide
        $API05 = "SHA1Managed" fullword ascii wide
        $API06 = "SHA256Managed" fullword ascii wide

        $dir1 = "%AppData% - Very Fast\\AppData\\" fullword wide
        $dir2 = "%SystemDrive% - Slow" fullword wide
        $dir3 = "%UsersFolder% - Fast" fullword wide
        $dir4 = "%AppData% - Very Fast\\AppData\\" fullword wide
        $dir5 = "%UsersFolder% - Fast" fullword wide
        $dir6 = "%AppData% - Very Fast\\AppData\\" fullword wide

        $ext01 = ".bat" fullword wide
        $ext02 = ".vbs" fullword wide
        $ext03 = ".zip" fullword wide
        $ext04 = ".jpg" fullword wide
        $ext05 = ".exe" fullword wide
       
        $comm = "w32tm /stripchart /computer:localhost /period:5 /dataonly /samples:2  1>nul" fullword wide
       
       
         

    condition:
        uint16(0) == 0x5a4d and (15 of ($str*) and 5 of ($API*) and 3 of ($dir*) and 3 of ($ext*) and ($comm))
}
