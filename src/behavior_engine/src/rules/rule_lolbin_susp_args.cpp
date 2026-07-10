#include "rules/rule_lolbin_susp_args.hpp"

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

using avcore::Severity;

struct LolbinPattern {
    const char* binary;
    const char* arg_substring;  // must be non-empty: bare execution is never a trigger
    const char* description;
    Severity    severity;       // Malicious = specific abuse technique, rarely legitimate;
                                // Suspicious = dual-use, seen in admin/dev tooling too
};

// Severity tiering is the core false-positive fix here. The previous version
// marked *every* match Malicious -- including dual-use patterns that legitimate
// software deployment relies on daily (msiexec /q silent installs, wmic
// /format:list queries) and even bare-execution matches (makecab/regasm/regsvcs
// with an empty arg) that fired on any launch. Now only patterns that map to a
// specific, rarely-legitimate abuse technique are Malicious; genuinely dual-use
// patterns are Suspicious (still actioned, but not screamed as confirmed malware).
constexpr LolbinPattern kPatterns[] = {
    // certutil (T1140, T1105) -- decode/download of payloads is rarely legit
    {"certutil.exe", "-decode",     "certutil used to decode an encoded payload",        Severity::Malicious},
    {"certutil.exe", "-decodehex",  "certutil used to decode a hex-encoded payload",     Severity::Malicious},
    {"certutil.exe", "-urlcache",   "certutil used to download via -urlcache",           Severity::Malicious},
    {"certutil.exe", "-verifyctl",  "certutil CTL verification with remote download",     Severity::Malicious},
    {"certutil.exe", "-encode",     "certutil encoding a file (possible obfuscation)",   Severity::Suspicious},
    // regsvr32 Squiblydoo (T1218.010)
    {"regsvr32.exe", "/i:http",     "regsvr32 Squiblydoo: remotely-hosted scriptlet",    Severity::Malicious},
    {"regsvr32.exe", "/i:ftp",      "regsvr32 Squiblydoo via FTP",                       Severity::Malicious},
    {"regsvr32.exe", "scrobj.dll",  "regsvr32 invoking scrobj.dll (scriptlet execution)", Severity::Malicious},
    {"regsvr32.exe", "/u /i:",      "regsvr32 unregister-then-run (evasion variant)",    Severity::Malicious},
    // rundll32 (T1218.011)
    {"rundll32.exe", "javascript:", "rundll32 executing inline javascript",              Severity::Malicious},
    {"rundll32.exe", "vbscript:",   "rundll32 executing inline VBScript",                Severity::Malicious},
    {"rundll32.exe", "comsvcs.dll", "rundll32 comsvcs.dll (MiniDump / DLL execution)",   Severity::Malicious},
    {"rundll32.exe", "url.dll,openurl", "rundll32 url.dll OpenURL download",             Severity::Malicious},
    {"rundll32.exe", "pcwutl.dll",  "rundll32 pcwutl.dll LaunchApplication (LOLBin)",    Severity::Suspicious},
    {"rundll32.exe", "zipfldr.dll", "rundll32 zipfldr.dll RouteTheCall (LOLBin)",        Severity::Suspicious},
    // mshta (T1218.005) -- remote/inline script execution
    {"mshta.exe", "http://",    "mshta executing a remotely-hosted HTA",                Severity::Malicious},
    {"mshta.exe", "https://",   "mshta executing a remotely-hosted HTA",                Severity::Malicious},
    {"mshta.exe", "ftp://",     "mshta executing a remotely-hosted HTA via FTP",        Severity::Malicious},
    {"mshta.exe", "vbscript:",  "mshta executing inline VBScript",                      Severity::Malicious},
    {"mshta.exe", "javascript:", "mshta executing inline JavaScript",                   Severity::Malicious},
    // bitsadmin (T1197)
    {"bitsadmin.exe", "/transfer",         "bitsadmin downloading a file via BITS",     Severity::Malicious},
    {"bitsadmin.exe", "/setnotifycmdline", "bitsadmin notify-cmd persistence via BITS", Severity::Malicious},
    {"bitsadmin.exe", "/addfile",          "bitsadmin adding a download file",          Severity::Suspicious},
    // msiexec (T1218.007) -- remote install is abuse; /q silent install is dual-use
    {"msiexec.exe", "http://",  "msiexec installing from remote URL",                   Severity::Malicious},
    {"msiexec.exe", "https://", "msiexec installing from remote URL",                   Severity::Malicious},
    {"msiexec.exe", "/i ftp://", "msiexec installing from FTP URL",                     Severity::Malicious},
    {"msiexec.exe", "/q",       "msiexec quiet install (dual-use: common in deployment)", Severity::Suspicious},
    // cmstp (T1218.003) -- UAC/AppLocker bypass
    {"cmstp.exe", "/s",  "cmstp silent install (AppLocker/UAC bypass)",                 Severity::Malicious},
    {"cmstp.exe", "/ni", "cmstp no-UI install (LOLBin execution)",                      Severity::Malicious},
    // wmic (T1047, T1220) -- only the remote/XSL-script forms; /format:list is benign
    {"wmic.exe", "process call create", "wmic spawning process (T1047)",               Severity::Suspicious},
    {"wmic.exe", "/format:http",        "wmic remote XSL script processing (T1220)",   Severity::Malicious},
    {"wmic.exe", ".xsl",                "wmic XSL script processing (T1220)",          Severity::Malicious},
    // odbcconf (T1218.008)
    {"odbcconf.exe", "/a {regsvr", "odbcconf REGSVR action (LOLBin DLL execution)",    Severity::Malicious},
    {"odbcconf.exe", "regsvr",     "odbcconf DLL registration (LOLBin execution)",     Severity::Suspicious},
    // pcalua (Application Compatibility)
    {"pcalua.exe", "-a", "pcalua.exe -a launching executable (AppLocker bypass)",      Severity::Suspicious},
    // expand (remote cabinet download)
    {"expand.exe", "http://", "expand.exe downloading cabinet from URL",               Severity::Malicious},
    // findstr (data staging from UNC) -- dual-use
    {"findstr.exe", "\\\\", "findstr reading from UNC path (possible data staging)",   Severity::Suspicious},
    // esentutl (T1003.003 NTDS copy, T1140 decode)
    {"esentutl.exe", "/y",  "esentutl /y file copy (LOLBin file staging)",             Severity::Suspicious},
    {"esentutl.exe", "/cp", "esentutl /cp database copy (NTDS staging)",               Severity::Suspicious},
    // diskshadow (T1003.003 VSS-based NTDS copy)
    {"diskshadow.exe", "/s", "diskshadow executing script (T1003.003 NTDS copy)",      Severity::Suspicious},
    // replace / print (LOLBin file copy) -- obscure, dual-use
    {"replace.exe", "/a",   "replace.exe /a adding files (LOLBin file drop)",          Severity::Suspicious},
    {"print.exe",   "/d:",  "print.exe /d: printing to a file path (LOLBin file copy)", Severity::Suspicious},
    // regasm / regsvcs (.NET assembly execution, T1218.009) -- require an assembly arg
    {"regasm.exe",  ".dll", "regasm.exe executing a .NET assembly (T1218.009)",        Severity::Suspicious},
    {"regsvcs.exe", ".dll", "regsvcs.exe executing a .NET assembly (T1218.009)",       Severity::Suspicious},
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
        detection.severity = pattern.severity;
        detection.target_path = event.image_path;
        detection.process_id = event.process_id;
        detection.parent_process_id = event.parent_process_id;
        detection.evidence = std::string(pattern.description) + ". Command line: " + event.command_line;
        return detection;
    }
    return std::nullopt;
}

} // namespace avbehavior::rules
