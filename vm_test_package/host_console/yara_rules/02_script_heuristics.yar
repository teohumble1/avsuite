rule Suspicious_PowerShell_EncodedDownload
{
    meta:
        description = "PowerShell script combining an encoded command with an inline web download -- common dropper pattern"
        severity = "malicious"
    strings:
        $encoded_command = "-EncodedCommand" nocase
        $invoke_iex = "IEX" nocase
        $invoke_expression = "Invoke-Expression" nocase
        $download_string = "DownloadString" nocase
        $web_client = "Net.WebClient" nocase
        $download_file = "DownloadFile" nocase
    condition:
        $encoded_command
        and (1 of ($invoke_iex, $invoke_expression))
        and (1 of ($download_string, $web_client, $download_file))
}
