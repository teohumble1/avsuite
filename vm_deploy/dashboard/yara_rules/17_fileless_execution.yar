// Fileless / memory-resident execution and persistence: real, specific WMI
// system class names, .NET reflection API combinations, and the one famous
// documented AMSI bypass field name -- not generic words like "fileless" or
// "memory".

rule Fileless_WMI_Permanent_Event_Subscription
{
    meta:
        description = "All three WMI permanent-event-subscription system classes present together (__EventFilter, CommandLineEventConsumer, __FilterToConsumerBinding) -- the standard WMI fileless persistence mechanism (T1546.003), rare to see all three named together outside deliberate WMI subscription code"
        severity = "critical"
    strings:
        $filter   = "__EventFilter" ascii wide
        $consumer = "CommandLineEventConsumer" ascii wide
        $binding  = "__FilterToConsumerBinding" ascii wide
    condition:
        all of them
}

rule Fileless_PowerShell_Reflective_Memory_Load
{
    meta:
        description = "PowerShell/.NET reflective assembly load ([System.Reflection.Assembly]::Load) combined with Marshal interop and a native VirtualAlloc call -- in-memory .NET loader pattern that never writes the loaded assembly to disk"
        severity = "malicious"
    strings:
        $reflect_load = "[System.Reflection.Assembly]::Load" ascii wide nocase
        $marshal      = "[System.Runtime.InteropServices.Marshal]" ascii wide nocase
        $valloc       = "VirtualAlloc" ascii wide
    condition:
        all of them
}

rule Fileless_Registry_Binary_Payload_Storage
{
    meta:
        description = "A Run-key registry path combined with a REG_BINARY value type and a long base64-shaped blob -- consistent with a payload staged as registry data rather than a file on disk (Poweliks/Kovter-style)"
        severity = "malicious"
    strings:
        $runkey     = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $regbinary  = "REG_BINARY" ascii wide nocase
        $b64_blob   = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii
    condition:
        all of them
}

rule Fileless_COM_Hijack_Temp_Path
{
    meta:
        description = "CLSID/InprocServer32 COM registration pointing at a DLL under a Temp directory -- COM hijacking persistence (T1546.015) using a throwaway staging path instead of a normal install location"
        severity = "malicious"
    strings:
        $inproc    = "InprocServer32" ascii wide
        $clsid     = "CLSID" ascii wide
        $temp_dll  = /\\Temp\\[A-Za-z0-9_.-]{1,40}\.dll/ nocase
    condition:
        all of them
}

rule Fileless_AMSI_InitFailed_Field_Tamper
{
    meta:
        description = "The exact documented AMSI bypass one-liner pattern: reflection targeting the private 'amsiInitFailed' field via [Ref].Assembly.GetType(...).GetField(..., NonPublic). This specific field name and reflection combo has no legitimate scripting use outside disabling AMSI."
        severity = "critical"
    strings:
        $amsi_field = "amsiInitFailed" ascii wide
        $reflection = "[Ref].Assembly.GetType" ascii wide nocase
        $nonpublic  = "NonPublic" ascii wide
    condition:
        all of them
}
