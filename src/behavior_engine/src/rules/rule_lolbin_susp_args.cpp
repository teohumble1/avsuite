#include "rules/rule_lolbin_susp_args.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

struct LolbinPattern {
    const char* binary;
    const char* arg_substring;
    const char* description;
};

constexpr LolbinPattern kPatterns[] = {
    // certutil (T1140, T1105)
    {"certutil.exe", "-decode",    "certutil used to decode an encoded payload"},
    {"certutil.exe", "-decodehex", "certutil used to decode a hex-encoded payload"},
    {"certutil.exe", "-urlcache",  "certutil used to download via -urlcache"},
    {"certutil.exe", "-verifyctl", "certutil CTL verification with remote download"},
    {"certutil.exe", "-encode",    "certutil encoding a file (possible obfuscation)"},
    // regsvr32 (T1218.010)
    {"regsvr32.exe", "/i:http",    "regsvr32 Squiblydoo: remotely-hosted scriptlet"},
    {"regsvr32.exe", "/i:ftp",     "regsvr32 Squiblydoo via FTP"},
    {"regsvr32.exe", "scrobj.dll", "regsvr32 invoking scrobj.dll (scriptlet execution)"},
    {"regsvr32.exe", "/u /i:",     "regsvr32 unregister-then-run (evasion variant)"},
    // rundll32 (T1218.011)
    {"rundll32.exe", "javascript:", "rundll32 executing inline javascript"},
    {"rundll32.exe", "vbscript:",   "rundll32 executing inline VBScript"},
    {"rundll32.exe", "comsvcs.dll", "rundll32 comsvcs.dll (MiniDump / DLL execution)"},
    {"rundll32.exe", "pcwutl.dll",  "rundll32 pcwutl.dll LaunchApplication (LOLBin)"},
    {"rundll32.exe", "url.dll,openurl", "rundll32 url.dll OpenURL download"},
    {"rundll32.exe", "zipfldr.dll", "rundll32 zipfldr.dll RouteTheCall (LOLBin)"},
    // mshta (T1218.005)
    {"mshta.exe", "http://",   "mshta executing a remotely-hosted HTA"},
    {"mshta.exe", "https://",  "mshta executing a remotely-hosted HTA"},
    {"mshta.exe", "ftp://",    "mshta executing a remotely-hosted HTA via FTP"},
    {"mshta.exe", "vbscript:", "mshta executing inline VBScript"},
    {"mshta.exe", "javascript:", "mshta executing inline JavaScript"},
    // bitsadmin (T1197)
    {"bitsadmin.exe", "/transfer",   "bitsadmin downloading a file via BITS"},
    {"bitsadmin.exe", "/addfile",    "bitsadmin adding a download file"},
    {"bitsadmin.exe", "/setnotifycmdline", "bitsadmin setting notification cmd (persistence via BITS)"},
    // msiexec (T1218.007)
    {"msiexec.exe", "/q",     "msiexec quiet install (possible silent malware install)"},
    {"msiexec.exe", "http://","msiexec installing from remote URL"},
    {"msiexec.exe", "https://","msiexec installing from remote URL"},
    {"msiexec.exe", "/i ftp://","msiexec installing from FTP URL"},
    // cmstp (T1218.003)
    {"cmstp.exe", "/s",     "cmstp silent install (AppLocker/UAC bypass)"},
    {"cmstp.exe", "/ni",    "cmstp no-UI install (LOLBin execution)"},
    // wmic (T1047, T1220)
    {"wmic.exe", "process call create", "wmic spawning process (T1047)"},
    {"wmic.exe", "/format:",            "wmic XSL script processing (T1220)"},
    // odbcconf (T1218.008)
    {"odbcconf.exe", "/a {regsvr",   "odbcconf REGSVR action (LOLBin DLL execution)"},
    {"odbcconf.exe", "regsvr",       "odbcconf DLL registration (LOLBin execution)"},
    // pcalua (Application Compatibility)
    {"pcalua.exe", "-a",     "pcalua.exe -a launching executable (AppLocker bypass)"},
    // expand (cabinet extraction to arbitrary paths)
    {"expand.exe", "http://", "expand.exe downloading cabinet from URL"},
    // findstr (file exfil / download from UNC)
    {"findstr.exe", "\\\\",   "findstr reading from UNC path (possible data staging)"},
    // esentutl (T1003.003 NTDS copy, T1140 decode)
    {"esentutl.exe", "/y",   "esentutl /y file copy (LOLBin file staging)"},
    {"esentutl.exe", "/cp",  "esentutl /cp database copy (NTDS staging)"},
    // makecab (compress and exfil)
    {"makecab.exe", "",      "makecab.exe executed (LOLBin for compressing files before exfil)"},
    // diskshadow (T1003.003 VSS-based NTDS copy)
    {"diskshadow.exe", "/s", "diskshadow executing script (T1003.003 NTDS copy)"},
    // replace.exe (overwrite files without standard copy)
    {"replace.exe", "/a",    "replace.exe /a adding files (LOLBin file drop)"},
    // print.exe (file copy LOLBin)
    {"print.exe",    "/d:",  "print.exe /d: printing to a file path (LOLBin file copy)"},
    // regasm / regsvcs (.NET assembly execution)
    {"regasm.exe",   "",     "regasm.exe executing .NET assembly (T1218.009)"},
    {"regsvcs.exe",  "",     "regsvcs.exe executing .NET assembly (T1218.009)"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleLolbinSuspiciousArgs::Evaluate(const ProcessEvent& event,
                                                                           const ProcessTree& /*tree*/) const {
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));
    const std::string command_line_lower = avcore::ToLowerAscii(event.command_line);

    for (const auto& pattern : kPatterns) {
        if (image_name != pattern.binary) continue;
        if (command_line_lower.find(pattern.arg_substring) == std::string::npos) continue;

        avcore::DetectionEvent detection;
        detection.rule_id = Id();
        detection.source = "behavior_engine";
        detection.severity = avcore::Severity::Malicious;
        detection.target_path = event.image_path;
        detection.process_id = event.process_id;
        detection.parent_process_id = event.parent_process_id;
        detection.evidence = std::string(pattern.description) + ". Command line: " + event.command_line;
        return detection;
    }
    return std::nullopt;
}

} // namespace avbehavior::rules
