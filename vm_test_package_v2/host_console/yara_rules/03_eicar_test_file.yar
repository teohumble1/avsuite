rule EICAR_Standard_AV_Test_File
{
    meta:
        description = "Industry-standard EICAR test string (eicar.org) -- intentionally benign, used to verify AV detection paths. Not real malware."
        severity = "malicious"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
