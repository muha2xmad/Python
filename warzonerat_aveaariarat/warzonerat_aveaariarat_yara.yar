
import "pe"

rule warzonerat_aveaariarat {
    meta:
        description = "Detects warzonerat/aveaariarat malware"
        author = "muha2xmad"
        date = "2023-08-24"
        hash1 = "f65a8af1100b56f2ebe014caeaa5bb2fbbca2da76cb99f3142354e31fbba5c8c"

    
    strings:       
        
        $browser_str001 = "\\Google\\Cache\\" fullword ascii wide
        $browser_str002 = "\\Google\\Chrome\\User Data\\Local State" fullword ascii wide
        $browser_str003 = "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies" fullword ascii wide
        $browser_str004 = "\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies" fullword ascii wide
        $browser_str005 = "\\Google\\Chrome\\User Data\\Default\\History" fullword ascii wide
        $browser_str006 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii wide
        $browser_str007 = "\\Google\\Chrome Beta\\User Data\\Default\\Login Data" fullword ascii wide
        $browser_str008 = "\\Microsoft\\Edge\\User Data\\Default\\Login Data" fullword ascii wide
        $browser_str009 = "\\logins.json" fullword ascii wide
        $browser_str010 = "\\Tencent\\QQBrowser\\User Data\\Local State" fullword ascii wide
        $browser_str011 = "\\UCBrowser\\User Data_i18n\\Default\\UC Login Data.17" fullword ascii wide
        $browser_str012 = "\\Google\\Media\\" fullword ascii wide
        $browser_str013 = "\\Google\\Cache\\" fullword ascii wide
        $browser_str014 = "\\Google\\Cache\\" fullword ascii wide

        $reg_str001 = "Software\\Microsoft\\Office\\15.0Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" fullword wide
        $reg_str002 = "software\\Aerofox\\FoxmailPreview" fullword wide
        $reg_str003 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" fullword wide
        $reg_str004 = "SYSTEM\\CurrentControlSet\\Services\\TermService\\Parameters" fullword wide
        $reg_str005 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" fullword wide
        $reg_str006 = "SYSTEM\\CurrentControlSet\\ControlTerminal Server\\AddIns\\Clip Redirector" fullword wide
        $reg_str007 = "SYSTEM\\CurrentControlSet\\Services\\TermService" fullword wide


        $str001 = "QAaR$43!QAFff" fullword wide
        $str002 = "?lst@@YAXHJ@Z" fullword wide
        $str003 = "RDPClip" fullword wide
        $str004 = "AllowMultipleTSSessions" fullword wide
        $str005 = "fDenyTSConnections" fullword wide
        $str006 = "svchost.exe -k" fullword wide
        $str007 = "#Window Name: " fullword wide
        $str008 = "profiles.ini" fullword wide
        $str009 = "-Clipboard Grabbed-" fullword wide
        $str010 = "#Window Name: " fullword wide
        $str011 = ".zip" fullword wide
        $str012 = "SeDebugPrivilege" fullword wide
        $str013 = "rudp" fullword wide
        $str014 = "rpdp" fullword wide

        $APIs_str001= "SHGetKnownFolderPath" fullword ascii
        $APIs_str002= "SHGetSpecialFolderPathW" fullword ascii
        $APIs_str003= "SHCreateDirectoryExW" fullword ascii
        $APIs_str004= "SHGetFolderPathW" fullword ascii
        $APIs_str005= "Wow64DisableWow64FsRedirection" fullword ascii

        $command001 = "powershell Add-MpPreference -ExclusionPath " fullword wide
        $command002 = "powerShell.exe -windowstyle hidden -Command \"Compress-Archive -Path  ' " fullword wide
        $command003 = "shutdown.exe /r /t 00" fullword wide
        $command004 = "cmd.exe /C ping 1.2.3.4 -n 4 -w 1000 > Nul & cmd.exe /C " fullword wide
        $command005 = "powershell Add-MpPreference -ExclusionPath " fullword wide
        $command006 = "%SystemRoot%\\System32\\termsrv.dll" fullword wide

    condition:
        uint16(0) == 0x5a4d and (10 of ($browser_str0*) or 5 of ($reg_str0*) or 10 of ($str0*) or 5 of ($APIs_str*) or 5 of ($command0*))
}
