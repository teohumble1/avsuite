// Ransomware technique indicators — anti-recovery commands, mass crypto API
// usage combined with file enumeration, and note-drop patterns. Deliberately
// avoids single generic English words as a standalone signal (the previous
// version of this file did exactly that and was deleted for it); every rule
// below requires a combination of specific, real command-line flags/API
// names/class names that are rarely all present together outside actual
// ransomware.

rule Ransomware_ShadowCopy_And_Recovery_Destruction
{
    meta:
        description = "vssadmin/wmic shadow-copy deletion combined with bcdedit anti-recovery flags -- the standard ransomware pre-encryption anti-recovery sequence (T1490)"
        severity = "critical"
    strings:
        $vssadmin      = "vssadmin" nocase
        $vss_delete    = "delete shadows" nocase
        $wmic_delete   = "shadowcopy delete" nocase
        $bcdedit       = "bcdedit" nocase
        $recoveryoff   = "recoveryenabled" nocase
        $ignorefail    = "ignoreallfailures" nocase
    condition:
        ($vssadmin and ($vss_delete or $wmic_delete))
        and ($bcdedit and ($recoveryoff or $ignorefail))
}

rule Ransomware_BitLocker_Extortion_Abuse
{
    meta:
        description = "manage-bde used with forced-recovery combined with lock/off flags -- BitLocker abused to lock the user out for extortion instead of its normal encryption-at-rest purpose. Requires two flags together (not just -forcerecovery alone) after the System32 audit showed a lone flag can coincidentally appear in large binary blobs (e.g. registry hive files)"
        severity = "suspicious"
    strings:
        $managebde     = "manage-bde" nocase
        $forcerecovery = "-forcerecovery" nocase
        $lock          = "-lock" nocase
        $off           = "-off" nocase
    condition:
        $managebde and $forcerecovery and ($lock or $off)
}

// NOTE: an earlier version of this file had a "Ransomware_Crypto_API_Mass_
// File_Encryption" rule that matched on CryptAcquireContext+CryptGenKey+
// CryptEncrypt+FindFirstFile/NextFile. Removed after the System32 FP audit:
// it fired on advapi32.dll, apphelp.dll, CertEnroll.dll and certutil.exe --
// advapi32.dll is literally the DLL that EXPORTS the CryptoAPI functions
// being matched, so it (and anything statically analyzed alongside it)
// trivially contains every one of those strings. Bare CryptoAPI-function-name
// presence is not a usable signal; the extension-list and note-drop rules
// below require additional non-implementer-specific context instead.

rule Ransomware_Extension_Enumeration_Plus_Encryption
{
    meta:
        description = "Five or more common document/archive/database extension literals present alongside a real encryption API call -- consistent with a file-type-targeting encryption routine"
        severity = "suspicious"
    strings:
        $ext1 = ".docx" ascii wide
        $ext2 = ".xlsx" ascii wide
        $ext3 = ".pptx" ascii wide
        $ext4 = ".pdf"  ascii wide
        $ext5 = ".zip"  ascii wide
        $ext6 = ".sql"  ascii wide
        $ext7 = ".mdb"  ascii wide
        $ext8 = ".jpg"  ascii wide
        $crypt = "CryptEncrypt" ascii
    condition:
        5 of ($ext*) and $crypt
}

rule Ransomware_AllCaps_Note_Drop_Plus_Crypto
{
    meta:
        description = "Two or more decorated ransom-note-style filenames embedded as literal strings, combined with a real encryption API -- consistent with a binary that both encrypts files and drops a note about it"
        severity = "malicious"
    strings:
        $note1 = "!!!READ_ME!!!" nocase
        $note2 = "DECRYPT_INSTRUCTION" nocase
        $note3 = "HOW_TO_DECRYPT" nocase
        $note4 = "RECOVERY_KEY" nocase
        $note5 = "YOUR_FILES" nocase
        $crypt = "CryptEncrypt" ascii
    condition:
        2 of ($note*) and $crypt
}

rule Ransomware_COM_ShadowCopy_Deletion
{
    meta:
        description = "WMI Win32_ShadowCopy class deleted via ExecMethod/DeleteInstance from code (COM-based, avoids spawning vssadmin.exe as a visible child process) -- stealthier variant of shadow-copy destruction. Downgraded to suspicious after the System32 audit: legitimate compatibility/diagnostic tooling (e.g. aitstatic.exe) can reference these same WMI class/method names without an anti-recovery intent"
        severity = "suspicious"
    strings:
        $wmi_class       = "Win32_ShadowCopy" ascii wide
        $delete_instance = "DeleteInstance" ascii wide
        $exec_method     = "ExecMethod" ascii wide
    condition:
        all of them
}
