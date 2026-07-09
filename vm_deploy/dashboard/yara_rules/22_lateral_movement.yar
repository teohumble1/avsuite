// Lateral-movement technique combinations: real WMI/DCOM class and method
// names, and Sysinternals PsExec's actual named-pipe/service artifacts.

rule LateralMovement_WMI_Remote_Process_Create
{
    meta:
        description = "WMI Win32_Process class combined with a remote ConnectServer call and ExecQuery -- remote process creation via WMI (T1047), the same class/method combo as the APT WMI rule but scoped here for lateral movement between hosts. Kept at suspicious, not malicious: the System32 audit found legitimate OEM/RMM management agents (e.g. Acer's AcerCCAgent.exe/AcerDIAgent.exe) use this exact combination for real remote hardware management"
        severity = "suspicious"
    strings:
        $wmi_proc = "Win32_Process" ascii wide
        $connect  = "ConnectServer" ascii wide
        $execq    = "ExecQuery" ascii wide
    condition:
        all of them
}

rule LateralMovement_PsExec_Named_Pipe_Service
{
    meta:
        description = "Sysinternals PsExec's actual default named pipe (\\pipe\\psexesvc) or its temporary service name (PSEXESVC) -- both are real, distinctive PsExec artifacts unlikely to appear outside genuine PsExec-based remote execution"
        severity = "critical"
    strings:
        $pipe     = "\\pipe\\psexesvc" nocase
        $svc_name = "PSEXESVC" nocase
    condition:
        any of them
}

rule LateralMovement_WinRM_Remote_Command_Execution
{
    meta:
        description = "WinRM combined with the Invoke-Command cmdlet and a -ComputerName target flag -- PowerShell Remoting used to execute commands on a remote host (T1021.006)"
        severity = "malicious"
    strings:
        $winrm       = "WinRM" nocase
        $invoke_cmd  = "Invoke-Command" nocase
        $computer_flag = "-ComputerName" nocase
    condition:
        all of them
}

rule LateralMovement_SMB_Admin_Share_File_Copy
{
    meta:
        description = "A literal ADMIN$ administrative-share UNC path combined with a file-copy/move API -- staging a payload onto a remote host over its hidden admin share. Some legitimate remote-deployment tooling also does this, kept at suspicious rather than higher"
        severity = "suspicious"
    strings:
        $admin_share = "\\ADMIN$" nocase
        $copyfile = "CopyFileW" ascii
        $movefile = "MoveFileW" ascii
    condition:
        $admin_share and ($copyfile or $movefile)
}

rule LateralMovement_DCOM_MMC_Application_Abuse
{
    meta:
        description = "The MMC20.Application DCOM object combined with its ExecuteShellCommand method -- the documented DCOM lateral-movement technique (T1021.003) that runs commands on a remote host without touching WMI or WinRM"
        severity = "critical"
    strings:
        $mmc = "MMC20.Application" ascii
        $exec_shell = "ExecuteShellCommand" ascii
    condition:
        all of them
}
