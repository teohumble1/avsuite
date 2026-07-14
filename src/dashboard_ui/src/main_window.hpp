#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <QMainWindow>
#include <QScrollArea>
#include <QTextEdit>

#include "avai/llm_assistant.hpp"

#include "avbehavior/process_event.hpp"
#include "avcore/config.hpp"
#include "avcore/detection_event.hpp"

class QTableWidget;
class QLabel;
class QPushButton;
class QStackedWidget;
class QButtonGroup;
class QFrame;
class QSystemTrayIcon;
class QCloseEvent;
class QCheckBox;
class QComboBox;
class QLineEdit;
class QPlainTextEdit;
class QSpinBox;
class QListWidget;
class QProgressBar;
class QTimer;
class QVBoxLayout;

namespace avdashboard { class PulseStatusCircle; }

namespace avengine {
class Engine;
}

namespace avdashboard {
class DetectionBarChart;
}

namespace avdashboard {

// Local mirror of avengine::ThreatIntelFetchResult so this header doesn't
// need to pull in the full engine.hpp -- entries are (sha256, note) pairs
// where note already carries the malware family + first-seen timestamp.
struct ThreatIntelUpdateResult {
    bool success = false;
    std::string error;
    std::vector<std::pair<std::string, std::string>> entries;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(avcore::Config config, QWidget* parent = nullptr);
    ~MainWindow() override;
    // Jumps to the AI Assistant page and prefills the input with `prompt`
    // (or shows a message if the local AI model isn't loaded yet). Lets
    // other pages (DLP, etc.) hand a finding off to the assistant.
    void OpenAiWithPrompt(const QString& prompt);

    // Merges (sha256, note) pairs into the hash blacklist, skipping any
    // sha256 already present, and refreshes the Hash List page's blacklist
    // table if it's already been built. Returns the number actually added.
    // Used by the Threat Intel page to import a pulled IOC feed.
    int ImportThreatIntelHashes(const std::vector<std::pair<std::string, std::string>>& sha256_and_note);

    // Blocking HTTP fetch of the abuse.ch MalwareBazaar recent-hash feed.
    // Safe to call from a background thread (does not touch any QWidget).
    ThreatIntelUpdateResult FetchThreatIntelFeed();

    // VirusTotal IOC lookups for the OSINT Hub page. Blocking -- call from
    // a background thread. `kind` is "hash", "ip", or "domain".
    QString LookupVtIoc(const QString& kind, const QString& value);

    // Configured avupdateserver base URL for the Self-Update page.
    QString UpdateServerUrl() const;

    // Real detection history from the engine's database, most recent first.
    // Used by the Alerts and Timeline pages instead of hardcoded example data.
    std::vector<avcore::DetectionEvent> GetRecentDetections(int limit) const;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void OnScanFolderClicked();
    void OnScanFilesClicked();
    void OnScanRegistryClicked();
    void OnScanMemoryClicked();
    void OnScanPersistenceClicked();
    void OnCancelScanClicked();
    void OnClearHistoryClicked();
    void OnExportDetectionsClicked();
    void OnExportListsClicked();
    void OnImportListsClicked();
    void OnSelectAllQuarantineClicked();
    void OnRestoreQuarantineClicked();
    void OnDeleteQuarantineClicked();

private:
    QWidget* BuildSidebar();
    QWidget* BuildHomePage();
    QWidget* BuildHistoryPage();
    QWidget* BuildQuarantinePage();
    QWidget* BuildSettingsPage();
    QWidget* BuildHashListPage();
    QWidget* BuildEtwPage();
    QWidget* BuildAiPage();
    QWidget* BuildNetworkPage();
    QWidget* BuildVpnPage();

    // Agentic AI tool-use loop -- implemented in main_window_ai_agent.cpp,
    // a separate TU from main_window_ai.cpp on purpose (see that file's
    // header comment: stacking this on the already-/Od-forced AI page TU
    // reliably crashed CL.exe). RunAiGenerationTurn kicks off one model
    // generation; on a TOOL_CALL response it hands off to HandleAiToolCall
    // (auto-runs read-only tools, shows a Confirm/Cancel bubble for
    // destructive ones), whose result feeds back in via
    // ContinueAiWithToolResult, which calls RunAiGenerationTurn again --
    // bounded by ai_tool_loop_count_.
    void RunAiGenerationTurn();
    void HandleAiToolCall(const std::string& tool_name, const std::string& args_json, int gen_id);
    void ContinueAiWithToolResult(const std::string& tool_name, const std::string& result_text, int gen_id);

    void SetupTrayIcon();
    void ShowThreatNotification(const avcore::DetectionEvent& event);

    void AppendDetectionRow(const avcore::DetectionEvent& event);
    void AppendEtwRow(const avbehavior::ProcessEvent& event);
    void LoadHistory();
    void ReloadQuarantineTable();
    void RefreshHomeStats();
    void RunScanInBackground(std::function<void()> work);
    std::int64_t SelectedQuarantineId() const;
    std::vector<std::int64_t> SelectedQuarantineIds() const;
    void GoToPage(int index);

    // Hash list page helpers
    void ReloadHashTable(QTableWidget* table, bool is_whitelist);
    void OnAddHashClicked(QTableWidget* table, bool is_whitelist);
    void OnRemoveHashClicked(QTableWidget* table, bool is_whitelist);

    // Settings page helpers
    void OnAddWatchDirClicked();
    void OnRemoveWatchDirClicked();
    void OnSaveSettingsClicked();

    std::unique_ptr<avengine::Engine> engine_;
    avcore::Config config_;

    QSystemTrayIcon* tray_icon_ = nullptr;

    QStackedWidget* pages_ = nullptr;
    QButtonGroup* nav_group_ = nullptr;
    QTableWidget* detections_table_ = nullptr;
    QTableWidget* quarantine_table_ = nullptr;
    QTableWidget* whitelist_table_ = nullptr;
    QTableWidget* blacklist_table_ = nullptr;
    QLabel* status_label_ = nullptr;
    QPushButton* scan_folder_button_ = nullptr;
    QPushButton* scan_files_button_  = nullptr;
    QPushButton* scan_registry_button_ = nullptr;
    QPushButton* scan_memory_button_ = nullptr;
    QPushButton* scan_persistence_button_ = nullptr;
    QPushButton* cancel_scan_button_ = nullptr;

    // Settings page widgets
    QListWidget* watch_dir_list_ = nullptr;
    QSpinBox* debounce_spin_ = nullptr;
    QCheckBox* schedule_enabled_check_ = nullptr;
    QComboBox* schedule_interval_combo_ = nullptr;
    QLineEdit* schedule_time_edit_ = nullptr;
    QLineEdit* schedule_path_edit_ = nullptr;
    QLineEdit* vt_key_edit_ = nullptr;
    QLineEdit* mb_key_edit_ = nullptr;

    // Home page stat labels
    QLabel* stat_scans_label_ = nullptr;
    QLabel* stat_detections_label_ = nullptr;
    QLabel* stat_malicious_label_ = nullptr;
    QLabel* stat_quarantine_label_ = nullptr;
    QLabel* protection_status_label_ = nullptr;
    QFrame* status_circle_ = nullptr;
    QLabel* status_icon_label_ = nullptr;

    // Home page component status indicators
    QLabel* folder_watch_status_ = nullptr;
    QLabel* etw_monitor_status_ = nullptr;
    QLabel* driver_status_ = nullptr;
    QLabel* net_monitor_status_ = nullptr;
    bool    net_monitor_enabled_ = true;
    QTimer* net_monitor_timer_   = nullptr;

    // Live protection posture, used to compute a real Security Score and the
    // "X/5 shields active" line (previously both hardcoded). Hash + YARA are
    // always-on scan layers; these three are the failable/toggleable ones.
    // Defaults mirror the UI's optimistic startup display (folder watch + ETW
    // assumed healthy until a failure event; the kernel driver is not loaded
    // until SYS.MINIFILTER_CONNECTED arrives).
    QLabel* shields_sub_label_ = nullptr;
    bool    folder_watch_ok_   = true;
    bool    etw_ok_            = true;
    bool    driver_ok_        = false;

    // Detection bar chart (threat analytics card)
    DetectionBarChart* detection_chart_ = nullptr;

    // Animated status circle (pulse rings)
    PulseStatusCircle* pulse_circle_ = nullptr;

    // Figma right-panel widgets
    QWidget*      realtime_chart_         = nullptr;  // MiniAreaChart
    QWidget*      score_ring_             = nullptr;  // ScoreRingWidget
    QVBoxLayout*  home_detections_layout_ = nullptr;

    // Figma shield icon widget (replaces PulseStatusCircle in status card)
    QWidget*      shield_widget_          = nullptr;  // ShieldIconWidget

    void RefreshHomeDetections();

    // Nav badge: counts Malicious detections that arrived while on another page
    int detection_unread_ = 0;
    QPushButton* nav_history_btn_ = nullptr;

    // AI assistant page
    std::unique_ptr<avai::LlmAssistant> ai_assistant_;
    QScrollArea* ai_chat_scroll_   = nullptr;
    QWidget*     ai_chat_widget_   = nullptr;
    QVBoxLayout* ai_chat_layout_   = nullptr;
    QLabel*      ai_typing_label_  = nullptr;
    QString      ai_typing_text_;
    QLineEdit*   ai_input_edit_    = nullptr;
    QPushButton* ai_send_btn_      = nullptr;
    QPushButton* ai_stop_btn_      = nullptr;
    QLabel*      ai_status_label_  = nullptr;
    QLineEdit*   ai_model_path_edit_ = nullptr;
    std::vector<avai::ChatMessage> ai_history_;
    bool         ai_sending_       = false;    // re-entrancy guard
    QWidget*     ai_thinking_widget_ = nullptr; // 3-dot animation while generating

    // AI avatar animation (AiAvatarWidget* — cast in main_window_ai.cpp)
    QWidget*     ai_avatar_widget_  = nullptr;
    QTimer*      ai_thinking_timer_ = nullptr;
    int          ai_thinking_dots_  = 0;
    int          ai_gen_id_         = 0;     // incremented each send; stale callbacks check this
    int          ai_tool_loop_count_ = 0;    // agentic tool-call rounds this turn; bounded to avoid infinite loops

    // Set once in BuildAiPage to a copy of its local addBubble lambda, so
    // main_window_ai_agent.cpp's member functions (a different TU) can add
    // chat bubbles too. Signature: (text, alignment, is_dots) -> QLabel*.
    std::function<QLabel*(const QString&, Qt::Alignment, bool)> ai_add_bubble_;

    // Scan progress (History page)
    QProgressBar* scan_progress_ = nullptr;
    QLabel* scan_files_label_ = nullptr;

    // ETW monitor page (page 5)
    QTableWidget* etw_table_ = nullptr;

    // Network monitor page (page 7) — C2 / zero-trust monitor
    QTableWidget* net_conn_table_      = nullptr;
    QLabel*       net_stat_total_      = nullptr;
    QLabel*       net_stat_estab_      = nullptr;
    QLabel*       net_stat_listen_     = nullptr;
    QLabel*       net_stat_suspicious_ = nullptr;
    QLabel*       net_stat_highrisk_   = nullptr;
    QLabel*       net_stat_cdn_        = nullptr;
    int           net_filter_mode_     = 0;   // 0=All 1=Suspicious 2=HighRisk
    QPushButton*  net_filter_all_      = nullptr;
    QPushButton*  net_filter_susp_     = nullptr;
    QPushButton*  net_filter_high_     = nullptr;

    // DNS hostname cache: "1.2.3.4" → "hostname.example.com"
    std::mutex                                  net_dns_mutex_;
    std::unordered_map<std::string,std::string> net_dns_cache_;
    std::atomic<bool>                           net_dns_running_{false};

    // Score cache: "proc|ip|port" → {score, label, cdn, timestamp_s}
    // Avoids re-scoring stable connections every 2.5s refresh
    struct NetScoreCache { int score; std::string label; std::string cdn; int64_t ts; };
    std::unordered_map<std::string, NetScoreCache> net_score_cache_;
    // User-verified safe: key → always shown as score 0
    std::unordered_set<std::string> net_safe_set_;
    int net_min_risk_threshold_ = 0;  // hide rows with risk < this value

    // Process Hunt panel (shown on row selection)
    QWidget*      net_hunt_panel_      = nullptr;
    QLabel*       net_hunt_title_lbl_  = nullptr;
    QLabel*       net_hunt_path_lbl_   = nullptr;
    QLabel*       net_hunt_parent_lbl_ = nullptr;
    QLabel*       net_hunt_risk_lbl_   = nullptr;
    QTableWidget* net_hunt_table_      = nullptr;
    QPushButton*  net_hunt_kill_btn_   = nullptr;
    uint32_t      net_hunted_pid_      = 0;

    void RefreshNetworkConnections();
    void HuntProcess(uint32_t pid);

    // VPN page
    enum class VpnState { Disconnected, Connecting, Connected, Disconnecting };
    VpnState        vpn_state_            = VpnState::Disconnected;
    int             vpn_selected_server_  = 0;
    int             vpn_protocol_         = 0;   // 0=WireGuard 1=OpenVPN 2=IKEv2
    int             vpn_connection_secs_  = 0;
    QTimer*         vpn_tick_timer_       = nullptr;
    QTimer*         vpn_stats_timer_      = nullptr;
    QTimer*         vpn_pulse_timer_      = nullptr;
    // Hero widgets
    QWidget*        vpn_orb_widget_       = nullptr;
    QLabel*         vpn_state_label_      = nullptr;
    QLabel*         vpn_server_label_     = nullptr;
    QLabel*         vpn_ip_label_         = nullptr;
    QLabel*         vpn_meta_label_       = nullptr;
    QLabel*         vpn_duration_label_   = nullptr;
    QPushButton*    vpn_connect_btn_      = nullptr;
    // Stats
    QLabel*         vpn_dl_label_         = nullptr;
    QLabel*         vpn_ul_label_         = nullptr;
    QLabel*         vpn_lat_label_        = nullptr;
    QLabel*         vpn_bw_label_         = nullptr;
    // Server list
    QWidget*        vpn_server_list_      = nullptr;
    QLineEdit*      vpn_search_edit_      = nullptr;
    int             vpn_filter_mode_      = 0;
    std::vector<int> vpn_favorites_;
    void VpnToggleConnect();
    void VpnSelectServer(int idx);
    void VpnUpdateHero();
    void VpnRefreshServerList(const QString& search = {});
};

} // namespace avdashboard
