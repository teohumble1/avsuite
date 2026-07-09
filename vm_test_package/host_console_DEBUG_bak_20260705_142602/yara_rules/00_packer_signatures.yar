rule UPX_Packed_Binary
{
    meta:
        description = "Binary packed with UPX -- not inherently malicious, but a common first step for malware trying to evade static signatures"
        severity = "info"
    strings:
        $upx_marker = "UPX!"
        $upx_info = "$Info: This file is packed with the UPX"
    condition:
        any of them
}
