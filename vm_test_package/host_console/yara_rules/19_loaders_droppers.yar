// Loader/dropper structural and behavioral indicators: embedded secondary
// PE overlays, download-then-inject chains, and specific documented LOLBAS
// technique combinations (fodhelper UAC bypass, MSBuild inline tasks).

rule Dropper_Embedded_Secondary_PE_Overlay
{
    meta:
        description = "The DOS stub text appears more than once in the same file -- a second embedded MZ/PE image bundled inside this one. Legitimate self-extracting installers also do this, so this is a weak structural lead, not a verdict."
        severity = "suspicious"
    strings:
        $dos_stub = "This program cannot be run in DOS mode" ascii
    condition:
        #dos_stub > 1 and filesize > 50KB
}

rule Dropper_Download_Then_Inject
{
    meta:
        description = "A file-download API (URLDownloadToFile/InternetOpenUrl) combined with the full WriteProcessMemory+CreateRemoteThread injection pair -- fetch-then-inject dropper chain"
        severity = "malicious"
    strings:
        $dl1 = "URLDownloadToFileA" ascii
        $dl2 = "URLDownloadToFileW" ascii
        $dl3 = "InternetOpenUrlA" ascii
        $dl4 = "InternetOpenUrlW" ascii
        $wpm = "WriteProcessMemory" ascii
        $crt = "CreateRemoteThread" ascii
    condition:
        ($dl1 or $dl2 or $dl3 or $dl4) and $wpm and $crt
}

rule Dropper_Self_Deleting_Batch_Idiom
{
    meta:
        description = "The cmd.exe batch self-reference token (%~f0) used to make a script delete its own file after running -- a distinctive real cmd.exe idiom with essentially no legitimate-installer use case"
        severity = "malicious"
    strings:
        $self_ref = "%~f0" ascii
        $del      = "del " nocase
        $fq       = "/f /q" nocase
    condition:
        $self_ref and ($del or $fq)
}

rule Dropper_PowerShell_EncodedCommand_From_Registry
{
    meta:
        description = "PowerShell -EncodedCommand/-enc invocation combined with reading a Run-key registry value via Get-ItemProperty -- payload staged in the registry, retrieved and decoded by a PowerShell stub"
        severity = "malicious"
    strings:
        $enc1    = "-EncodedCommand" nocase
        $enc2    = "-enc " nocase
        $getprop = "Get-ItemProperty" nocase
        $runkey  = "CurrentVersion\\Run" nocase
    condition:
        ($enc1 or $enc2) and $getprop and $runkey
}

rule Dropper_Fodhelper_UAC_Bypass
{
    meta:
        description = "fodhelper.exe referenced alongside the DelegateExecute registry key under ms-settings\\Shell\\Open\\command -- the documented fodhelper.exe UAC-bypass registry hijack (T1548.002)"
        severity = "critical"
    strings:
        $fodhelper   = "fodhelper.exe" nocase
        $delegate    = "DelegateExecute" nocase
        $ms_settings = "ms-settings\\Shell\\Open\\command" nocase
    condition:
        all of them
}

rule Dropper_MSBuild_Inline_Task_Execution
{
    meta:
        description = "MSBuild project XML using CodeTaskFactory/TaskFactory with an inline <Task> element -- the documented MSBuild inline-task code-execution technique (T1127.001), used to run arbitrary C# via a trusted, signed Microsoft binary"
        severity = "malicious"
    strings:
        $msbuild = "MSBuild" ascii
        $task_factory = "TaskFactory" ascii
        $code_task_factory = "CodeTaskFactory" ascii
        $task_tag = "<Task" ascii
    condition:
        all of them
}
