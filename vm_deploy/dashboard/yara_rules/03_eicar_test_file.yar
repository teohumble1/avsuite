rule EICAR_Standard_AV_Test_File
{
    meta:
        description = "Industry-standard EICAR test string (eicar.org) -- intentionally benign, used to verify AV detection paths. Not real malware."
        severity = "malicious"
    strings:
        // AMSI-fed content (e.g. PowerShell script text) arrives as UTF-16LE,
        // not ASCII/UTF-8 -- match both so the same rule works for on-disk
        // file scans and AMSI script scans.
        $eicar_ascii = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
        $eicar_wide  = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" wide
    condition:
        any of them
}
