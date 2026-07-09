#include "rules/rule_av_killer_child.hpp"

#include <array>
#include <string>

#include "avcore/path_utils.hpp"

namespace avbehavior::rules {

namespace {

// AV/EDR service and process names targeted by AV-killer tools
constexpr const char* kAvTargets[] = {
    // Windows Defender / Security Center
    "windefend", "msmpeng.exe", "mssense.exe", "securityhealthservice",
    "wdnissvc", "wdnisusr.exe", "mpssvc", "mpcmdrun.exe",
    "securityhealthsystray.exe", "smartscreen.exe",
    // Microsoft Endpoint Protection / SCCM
    "ccmexec.exe", "sccm", "scepsvr",
    // Kaspersky
    "avp.exe", "avpui.exe", "kavtray.exe", "klnagent", "kavfs.exe",
    "kav.exe", "avp32.exe", "kavsvc.exe",
    // McAfee / Trellix
    "mfefire", "mfemms", "mfevtp", "mcafee",
    "mcshield.exe", "vshields.exe", "vstskmgr.exe", "mfewc.exe",
    "mcapexe.exe", "mctray.exe",
    // Sophos
    "savservice", "sophosssp", "savsvc.exe", "sophosfimservice",
    "hmpalerttool.exe", "sophossafestore", "manageengine",
    // Norton / Symantec
    "ccsvchst.exe", "nsvctrl.exe", "rtvscan.exe", "navapsvc.exe",
    "norton360.exe", "nscsrvce.exe", "symantec", "sndsrvc.exe",
    // Avast / AVG
    "avastui.exe", "avastsvc.exe", "avgui.exe", "avgsvc.exe",
    "aswidsagent.exe", "aswengsrv.exe", "avgnt.exe", "avgwdsvc.exe",
    // Avira
    "avscan.exe", "avguard.exe", "avcenter.exe", "avwebgrd.exe",
    // Bitdefender
    "bdservicehost.exe", "bdredline.exe", "bdagent.exe", "vsserv.exe",
    "seccenter.exe", "bdwtxag.exe", "bdntwrk.exe",
    // ESET
    "ekrn.exe", "egui.exe", "eamsi.exe", "eset",
    "nod32krn.exe", "nod32kui.exe",
    // Malwarebytes
    "mbam.exe", "mbamservice", "mbamgui.exe", "mbamtray.exe", "mbae.exe",
    // Trend Micro
    "tmlisten.exe", "pccntmon.exe", "coreserviceshell.exe", "uiainit.exe",
    "ds_agent.exe", "ntrtscan.exe", "tmbmsrv.exe",
    // Palo Alto Cortex / CrowdStrike Falcon
    "cyserver.exe", "csagent.exe", "csfalconservice.exe",
    "falcond.exe", "falcon-sensor",
    // Carbon Black
    "cbdefense.exe", "cb.exe", "cbsensor.exe",
    // SentinelOne
    "sentinelone.exe", "sentinelagent.exe", "sentinelservicehost.exe",
    // Cylance
    "cylancesvc.exe", "cylance.exe",
    // Webroot
    "wrsa.exe", "wrsvc.exe",
    // F-Secure
    "fshoster32.exe", "fsavd.exe", "fsma32.exe",
    // G Data
    "avshadow.exe", "gdatascanserver.exe",
    // Emsisoft
    "a2guard.exe", "a2start.exe", "a2service.exe",
    // Comodo
    "cis.exe", "cmdagent.exe", "cavwp.exe",
    // Generic
    "360tray.exe", "360sd.exe", "zhudongfangyu.exe",
};

bool ContainsAvTarget(const std::string& cmd_lower) {
    for (const char* target : kAvTargets) {
        if (cmd_lower.find(target) != std::string::npos) return true;
    }
    return false;
}

struct KillerPattern {
    const char* binary;       // executable name (lowercase)
    const char* arg_trigger;  // required substring in command line
    const char* description;
};

constexpr KillerPattern kPatterns[] = {
    // sc.exe stop/delete/config targeting AV service
    {"sc.exe",      "stop",   "sc.exe stopping a service"},
    {"sc.exe",      "delete", "sc.exe deleting a service"},
    {"sc.exe",      "config", "sc.exe disabling a service"},
    // net / net1
    {"net.exe",     "stop",   "net.exe stopping a service"},
    {"net1.exe",    "stop",   "net1.exe stopping a service"},
    // taskkill
    {"taskkill.exe", "/im",   "taskkill targeting a process by name"},
    {"taskkill.exe", "/pid",  "taskkill targeting a process by PID"},
    // PowerShell Stop-Service / Stop-Process
    {"powershell.exe", "stop-service",  "PowerShell Stop-Service"},
    {"powershell.exe", "stop-process",  "PowerShell Stop-Process"},
    {"pwsh.exe",       "stop-service",  "pwsh Stop-Service"},
    {"pwsh.exe",       "stop-process",  "pwsh Stop-Process"},
};

} // namespace

std::optional<avcore::DetectionEvent> RuleAvKillerChild::Evaluate(
    const ProcessEvent& event, const ProcessTree& /*tree*/) const
{
    const std::string image_name = avcore::ToLowerAscii(avcore::Basename(event.image_path));
    const std::string cmd_lower  = avcore::ToLowerAscii(event.command_line);

    for (const auto& pat : kPatterns) {
        if (image_name != pat.binary) continue;
        if (cmd_lower.find(pat.arg_trigger) == std::string::npos) continue;
        if (!ContainsAvTarget(cmd_lower)) continue;

        avcore::DetectionEvent det;
        det.rule_id           = Id();
        det.source            = "behavior_engine";
        det.severity          = avcore::Severity::Malicious;
        det.target_path       = event.image_path;
        det.process_id        = event.process_id;
        det.parent_process_id = event.parent_process_id;
        det.evidence          = std::string(pat.description)
                                + " targeting a security product. Command line: "
                                + event.command_line;
        return det;
    }
    return std::nullopt;
}

} // namespace avbehavior::rules
