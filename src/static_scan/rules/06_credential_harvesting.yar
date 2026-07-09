rule Mimikatz_Keywords
{
    meta:
        description = "Mimikatz command keywords — sekurlsa, lsadump, privilege modules"
        severity = "malicious"
    strings:
        $sekurlsa      = "sekurlsa::"    nocase
        $lsadump       = "lsadump::"     nocase
        $privilege_dbg = "privilege::debug" nocase
        $token_elev    = "token::elevate"   nocase
        $wdigest       = "sekurlsa::wdigest" nocase
        $logonpw       = "sekurlsa::logonpasswords" nocase
    condition:
        2 of them
}

rule LSASS_Dump_Indicators
{
    meta:
        description = "LSASS memory dump via MiniDumpWriteDump or comsvcs.dll — credential theft"
        severity = "malicious"
    strings:
        $lsass            = "lsass"              nocase
        $minidump         = "MiniDumpWriteDump"  nocase
        $comsvcs          = "comsvcs.dll"        nocase
        $comsvcs_minidump = "MiniDump"           nocase
        $rundll_comsvcs   = "rundll32"           nocase
    condition:
        $lsass and (
            $minidump
            or ($rundll_comsvcs and $comsvcs and $comsvcs_minidump)
        )
}
