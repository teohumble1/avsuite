// main_window_ai_agent.cpp — Agentic AI tool-use loop for the AI Assistant
// page (#6 in the backlog: "LLM tool-use to control AV -- auto hunt/
// quarantine/kill, ask on destructive").
//
// Deliberately a separate translation unit from main_window_ai.cpp: that
// file already forces /Od to work around an MSVC 14.44 ICE on Qt+templates
// (see CMakeLists.txt), and the first version of this feature was written
// as a mutually-recursive shared_ptr<std::function<...>> chain declared
// inline inside BuildAiPage -- CL.exe crashed on it 3/3 attempts (0xC0000005,
// then 0xC0000409, then 0xC0000005 again), including after retries that fix
// the transient crash this codebase otherwise sees. Moving the same logic
// into plain MainWindow member functions in a fresh TU (no nested-lambda
// self-reference, no /Od baggage from the giant AI page file) compiles
// clean. BuildAiPage still owns the chat UI and just calls RunAiGenerationTurn.
//
// Protocol: the model can reply with exactly one line
//   TOOL_CALL: {"tool":"<name>","args":{...}}
// to request a tool. Read-only tools (get_stats, list_recent_detections,
// list_quarantine, list_processes, scan_file, scan_directory) run
// immediately on a background thread. Destructive tools (kill_process,
// quarantine_delete, quarantine_restore) show an inline Confirm/Cancel
// bubble in the chat and only run if the user clicks Confirm. Either way
// the result is fed back into the chat history as a user-role
// "[TOOL_RESULT ...]" message and generation continues automatically,
// bounded by ai_tool_loop_count_ (see main_window.hpp) to avoid infinite
// loops. ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

#include <nlohmann/json.hpp>

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QPushButton>
#include <QScrollBar>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include "avcore/severity.hpp"
#include "avengine/engine.hpp"
#include "av_quit_guard.hpp"

namespace avdashboard {
namespace {

struct ToolCallInfo {
    std::string name;
    nlohmann::json args;
};

std::optional<ToolCallInfo> ParseToolCall(const QString& text) {
    const QString marker = QStringLiteral("TOOL_CALL:");
    const int idx = text.indexOf(marker);
    if (idx < 0) return std::nullopt;
    QString json_part = text.mid(idx + marker.size()).trimmed();
    const int nl = json_part.indexOf('\n');
    if (nl >= 0) json_part = json_part.left(nl).trimmed();
    try {
        auto j = nlohmann::json::parse(json_part.toStdString());
        ToolCallInfo tc;
        tc.name = j.value("tool", std::string());
        tc.args = j.value("args", nlohmann::json::object());
        if (tc.name.empty()) return std::nullopt;
        return tc;
    } catch (...) {
        return std::nullopt;
    }
}

const std::set<std::string>& DestructiveTools() {
    static const std::set<std::string> s = { "kill_process", "quarantine_delete", "quarantine_restore" };
    return s;
}

QString FormatDetectionsShort(const std::vector<avcore::DetectionEvent>& dets, int max_n) {
    if (dets.empty()) return QString::fromUtf8("(khong co)");
    QString out;
    int n = 0;
    for (const auto& d : dets) {
        if (n++ >= max_n) break;
        out += QString::fromUtf8("- [%1] %2: %3\n")
            .arg(QString::fromUtf8(std::string(avcore::ToString(d.severity)).c_str()))
            .arg(QString::fromStdString(d.rule_id))
            .arg(QString::fromStdString(d.target_path));
    }
    return out;
}

std::vector<std::pair<DWORD, std::wstring>> SnapshotProcesses(int max_n) {
    std::vector<std::pair<DWORD, std::wstring>> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            out.emplace_back(pe.th32ProcessID, pe.szExeFile);
        } while (Process32NextW(snap, &pe) && static_cast<int>(out.size()) < max_n);
    }
    CloseHandle(snap);
    return out;
}

// Blocks scan_directory targets that are a drive root or a top-level system
// directory -- these can take hours and hammer CPU/disk with no way for the
// user to know it's happening (the AI could pick one on its own, since
// scan_directory isn't in DestructiveTools() and doesn't ask for confirm).
bool IsTooBroadToAutoScan(const std::string& path) {
    std::string p = path;
    for (auto& c : p) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    // Strip a trailing slash/backslash so "C:\" and "C:" both match.
    while (!p.empty() && (p.back() == '\\' || p.back() == '/')) p.pop_back();

    // Bare drive letter root, e.g. "c:", "d:".
    if (p.size() == 2 && p[1] == ':') return true;

    static const char* kBroadRoots[] = {
        "c:\\windows", "c:\\program files", "c:\\program files (x86)",
        "c:\\programdata", "c:\\users", nullptr
    };
    for (int i = 0; kBroadRoots[i]; ++i) if (p == kBroadRoots[i]) return true;
    return false;
}

// Runs a non-destructive tool. Safe to call from a background thread --
// touches only engine_ (thread-safe, per its use elsewhere off the GUI
// thread) and Win32 process enumeration, no QWidget access.
std::string ExecuteReadOnlyTool(avengine::Engine* engine, const ToolCallInfo& tc) {
    std::ostringstream out;
    if (tc.name == "get_stats") {
        const auto s = engine->GetStats();
        out << "Tong so lan quet: " << s.total_scans
            << ", tong phat hien: " << s.total_detections
            << ", malicious: " << s.malicious_detections
            << ", dang trong quarantine: " << s.active_quarantine_count;
    } else if (tc.name == "list_recent_detections") {
        const int limit = tc.args.value("limit", 10);
        const auto dets = engine->RecentDetections(std::clamp(limit, 1, 50));
        out << FormatDetectionsShort(dets, std::clamp(limit, 1, 50)).toStdString();
    } else if (tc.name == "list_quarantine") {
        const auto q = engine->ListQuarantine();
        if (q.empty()) { out << "(quarantine dang trong)"; }
        for (size_t i = 0; i < q.size() && i < 30; ++i) {
            out << "- id=" << q[i].id << " " << q[i].original_path
                << (q[i].restored ? " [da restore]" : "") << "\n";
        }
    } else if (tc.name == "list_processes") {
        const auto procs = SnapshotProcesses(60);
        for (const auto& [pid, name] : procs) {
            out << "- PID " << pid << "  "
                << QString::fromWCharArray(name.c_str()).toStdString() << "\n";
        }
    } else if (tc.name == "scan_file") {
        const std::string path = tc.args.value("path", std::string());
        if (path.empty()) { out << "Thieu tham so path."; }
        else {
            const auto before = engine->GetStats();
            engine->ScanFile(path);
            const auto after = engine->GetStats();
            out << "Da quet " << path << ". Phat hien moi: "
                << (after.total_detections - before.total_detections);
        }
    } else if (tc.name == "scan_directory") {
        const std::string path = tc.args.value("path", std::string());
        if (path.empty()) { out << "Thieu tham so path."; }
        else if (IsTooBroadToAutoScan(path)) {
            // A whole-drive-root scan (e.g. "C:\") is not something the
            // model should ever kick off unilaterally on a read-only tool --
            // it can run for hours and there was no way to interrupt it from
            // this chat before (fixed separately: Stop now calls
            // engine->CancelScan()), but the better fix is to not let it
            // start in the first place for a target this broad.
            out << "Tu choi: '" << path << "' qua rong (goc o dia hoac thu muc he thong). "
                << "Hay chi dinh mot thu muc con the hon (vd Documents, Downloads, "
                << "hoac mot du an cu the).";
        } else {
            const auto before = engine->GetStats();
            engine->ScanDirectory(path);
            const auto after = engine->GetStats();
            out << "Da quet thu muc " << path << ". So file quet them: "
                << (after.total_scans - before.total_scans)
                << ", phat hien moi: " << (after.total_detections - before.total_detections);
        }
    } else {
        out << "Khong nhan dien duoc cong cu '" << tc.name << "'.";
    }
    return out.str();
}

QString DescribeDestructiveCall(const ToolCallInfo& tc) {
    if (tc.name == "kill_process") {
        return QString::fromUtf8("AI muon DUNG tien trinh PID %1. Ban co xac nhan khong?")
            .arg(tc.args.value("pid", 0));
    }
    if (tc.name == "quarantine_delete") {
        return QString::fromUtf8("AI muon XOA VINH VIEN file quarantine id=%1 (khong the hoan tac). Ban co xac nhan khong?")
            .arg(tc.args.value("id", 0));
    }
    if (tc.name == "quarantine_restore") {
        return QString::fromUtf8("AI muon KHOI PHUC file quarantine id=%1 ve vi tri goc. Ban co xac nhan khong?")
            .arg(tc.args.value("id", 0));
    }
    return QString::fromUtf8("AI muon thuc hien hanh dong '") + QString::fromStdString(tc.name) + QString::fromUtf8("'. Xac nhan?");
}

} // namespace

void MainWindow::RunAiGenerationTurn() {
    const int gen_id = ++ai_gen_id_;
    ai_typing_text_.clear();
    ai_thinking_dots_ = 0;
    ai_typing_label_ = ai_add_bubble_(QString::fromUtf8(""), Qt::AlignLeft, false);

    if (!ai_thinking_timer_) {
        ai_thinking_timer_ = new QTimer(this);
        ai_thinking_timer_->setInterval(420);
    }
    ai_thinking_timer_->disconnect();
    connect(ai_thinking_timer_, &QTimer::timeout, this, [this] {
        if (ai_typing_label_ && ai_typing_text_.isEmpty()) {
            ai_thinking_dots_ = (ai_thinking_dots_ + 1) % 4;
            const char* dots[] = {
                "\xe2\x80\xa2", "\xe2\x80\xa2 \xe2\x80\xa2",
                "\xe2\x80\xa2 \xe2\x80\xa2 \xe2\x80\xa2", "\xe2\x80\xa2 \xe2\x80\xa2"
            };
            ai_typing_label_->setAlignment(Qt::AlignCenter);
            ai_typing_label_->setStyleSheet(
                "color:rgba(255,122,0,140); font-size:13pt; background:transparent;");
            ai_typing_label_->setText(QString::fromUtf8(dots[ai_thinking_dots_]));
        } else {
            ai_thinking_timer_->stop();
        }
    });
    ai_thinking_timer_->start();

    ai_assistant_->GenerateAsync(ai_history_,
        [this, gen_id](const std::string& token, bool done) {
            QMetaObject::invokeMethod(this, [this, gen_id, token, done] {
                if (gen_id != ai_gen_id_) return; // stale -- aborted gen

                if (!token.empty() && ai_typing_label_) {
                    if (ai_typing_text_.isEmpty()) {
                        if (ai_thinking_timer_) ai_thinking_timer_->stop();
                        ai_typing_label_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
                        ai_typing_label_->setStyleSheet(
                            "color:#ECE4DA; font-size:10pt; background:transparent;");
                    }
                    ai_typing_text_ += QString::fromUtf8(token.c_str());
                    ai_typing_label_->setTextFormat(Qt::PlainText);
                    ai_typing_label_->setText(ai_typing_text_ + QString::fromUtf8("\xe2\x96\x8c"));
                    ai_chat_scroll_->verticalScrollBar()->setValue(
                        ai_chat_scroll_->verticalScrollBar()->maximum());
                }

                if (!done) return;

                if (ai_thinking_timer_) ai_thinking_timer_->stop();
                const auto toolcall = ParseToolCall(ai_typing_text_);

                if (ai_typing_label_) {
                    if (ai_typing_text_.isEmpty()) {
                        ai_typing_label_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
                        ai_typing_label_->setStyleSheet(
                            "color:#ECE4DA; font-size:10pt; background:transparent;");
                        ai_typing_label_->setText(
                            QString::fromUtf8("(Kh\xc3\xb4ng c\xc3\xb3 ph\xe1\xba\xa3n h\xe1\xbb\x93i)"));
                    } else if (toolcall) {
                        // Don't show the raw TOOL_CALL JSON to the user.
                        ai_typing_label_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
                        ai_typing_label_->setStyleSheet(
                            "color:#8B7355; font-size:9.5pt; font-style:italic; background:transparent;");
                        ai_typing_label_->setText(
                            QString::fromUtf8("\xf0\x9f\x94\xa7 \xc4\x90" "ang g\xe1\xbb\x8di c\xc3\xb4ng c\xe1\xbb\xa5: ") +
                            QString::fromStdString(toolcall->name));
                    } else {
                        // Plain text here (not MarkdownToHtml -- that helper has internal
                        // linkage in main_window_ai.cpp's anonymous namespace, not callable
                        // from this TU). Only affects markdown rendering of AI replies that
                        // follow a tool call; replies with no tool call still render via the
                        // normal path in main_window_ai.cpp.
                        ai_typing_label_->setTextFormat(Qt::PlainText);
                        ai_typing_label_->setText(ai_typing_text_);
                    }
                }
                if (!ai_typing_text_.isEmpty())
                    ai_history_.push_back({"assistant", ai_typing_text_.toStdString()});
                ai_typing_label_ = nullptr;

                if (toolcall && ai_tool_loop_count_ < 4) {
                    ++ai_tool_loop_count_;
                    HandleAiToolCall(toolcall->name, toolcall->args.dump(), gen_id);
                    return; // stays "busy" -- HandleAiToolCall continues the loop
                }
                if (toolcall) {
                    ai_add_bubble_(QString::fromUtf8(
                        "(\xc4\x90\xc3\xa3 \xc4\x91\xe1\xba\xa1t gi\xe1\xbb\x9bi h\xe1\xba\xa1n g\xe1\xbb\x8di c\xc3\xb4ng c\xe1\xbb\xa5 li\xc3\xaan ti\xe1\xba\xbfp, "
                        "d\xe1\xbb\xabng l\xe1\xba\xa1i \xe1\xbb\x9f \xc4\x91\xc3\xa2y.)"), Qt::AlignLeft, false);
                }

                ai_tool_loop_count_ = 0;
                ai_sending_ = false;
                ai_send_btn_->setEnabled(true);
                ai_input_edit_->setEnabled(true);
                ai_input_edit_->setFocus();
                ai_stop_btn_->setVisible(false);
            }, Qt::QueuedConnection);
        });
}

void MainWindow::HandleAiToolCall(const std::string& tool_name, const std::string& args_json, int gen_id) {
    ToolCallInfo tc;
    tc.name = tool_name;
    try { tc.args = nlohmann::json::parse(args_json); } catch (...) { tc.args = nlohmann::json::object(); }

    if (!DestructiveTools().count(tc.name)) {
        std::thread([this, tc, gen_id] {
            const std::string result = ExecuteReadOnlyTool(engine_.get(), tc);
            if (!AppQuitting().load()) {
                QMetaObject::invokeMethod(this, [this, tc, result, gen_id] {
                    ContinueAiWithToolResult(tc.name, result, gen_id);
                }, Qt::QueuedConnection);
            }
        }).detach();
        return;
    }

    // Inline confirm/cancel bubble -- nothing executes until the user clicks.
    auto* stretchItem = ai_chat_layout_->itemAt(ai_chat_layout_->count() - 1);
    if (stretchItem && stretchItem->spacerItem()) {
        ai_chat_layout_->removeItem(stretchItem);
        delete stretchItem;
    }
    auto* row = new QWidget(ai_chat_widget_);
    row->setStyleSheet("background:transparent;");
    auto* row_l = new QHBoxLayout(row);
    row_l->setContentsMargins(16, 3, 16, 3);
    row_l->setSpacing(10);
    auto* card = new QFrame(row);
    card->setMaximumWidth(460);
    card->setStyleSheet(
        "QFrame { background:#241512; border:1px solid rgba(255,90,90,90); border-radius:12px; }");
    auto* card_l = new QVBoxLayout(card);
    card_l->setContentsMargins(14, 12, 14, 12);
    card_l->setSpacing(8);
    auto* lbl = new QLabel(QString::fromUtf8("\xe2\x9a\xa0\xef\xb8\x8f ") + DescribeDestructiveCall(tc), card);
    lbl->setWordWrap(true);
    lbl->setStyleSheet("color:#ECE4DA; font-size:9.5pt; background:transparent;");
    card_l->addWidget(lbl);
    auto* btn_row = new QHBoxLayout();
    btn_row->setSpacing(8);
    auto* confirm_btn = new QPushButton(QString::fromUtf8("X\xc3\xa1" "c nh\xe1\xba\xadn"), card);
    confirm_btn->setCursor(Qt::PointingHandCursor);
    confirm_btn->setStyleSheet(
        "QPushButton { background:#FF5A6A; border:none; border-radius:8px; color:#fff;"
        " font-weight:700; padding:7px 18px; } QPushButton:hover { background:#FF3A5A; }"
        " QPushButton:disabled { background:#3A1F1F; color:#8B7355; }");
    auto* cancel_btn = new QPushButton(QString::fromUtf8("H\xe1\xbb\xa7y"), card);
    cancel_btn->setCursor(Qt::PointingHandCursor);
    cancel_btn->setStyleSheet(
        "QPushButton { background:#241708; border:1px solid #33261A; border-radius:8px; color:#C7B6A2;"
        " padding:7px 18px; } QPushButton:hover { background:#33261A; }"
        " QPushButton:disabled { background:#1C1108; color:#8B7355; }");
    btn_row->addWidget(confirm_btn);
    btn_row->addWidget(cancel_btn);
    btn_row->addStretch();
    card_l->addLayout(btn_row);
    row_l->addWidget(card);
    row_l->addStretch();
    ai_chat_layout_->addWidget(row);
    ai_chat_layout_->addStretch();
    ai_chat_scroll_->verticalScrollBar()->setValue(ai_chat_scroll_->verticalScrollBar()->maximum());

    connect(confirm_btn, &QPushButton::clicked, card, [this, tc, gen_id, confirm_btn, cancel_btn]() {
        confirm_btn->setEnabled(false);
        cancel_btn->setEnabled(false);
        std::string result;
        if (tc.name == "kill_process") {
            const DWORD pid = static_cast<DWORD>(tc.args.value("pid", 0));
            HANDLE h = pid ? OpenProcess(PROCESS_TERMINATE, FALSE, pid) : nullptr;
            if (h) {
                const bool ok = TerminateProcess(h, 1);
                CloseHandle(h);
                result = ok ? "Da dung tien trinh." : "TerminateProcess that bai.";
            } else {
                result = "Khong mo duoc tien trinh (khong ton tai hoac thieu quyen).";
            }
        } else if (tc.name == "quarantine_delete") {
            const std::int64_t id = tc.args.value("id", 0);
            result = (id && engine_->DeleteQuarantine(id))
                ? "Da xoa vinh vien." : "Xoa that bai (id khong hop le hoac da xoa).";
            ReloadQuarantineTable();
            RefreshHomeStats();
        } else if (tc.name == "quarantine_restore") {
            const std::int64_t id = tc.args.value("id", 0);
            result = (id && engine_->RestoreFromQuarantine(id))
                ? "Da khoi phuc ve vi tri goc." : "Restore that bai (id khong hop le hoac da restore).";
            ReloadQuarantineTable();
            RefreshHomeStats();
        } else {
            result = "Cong cu khong ho tro.";
        }
        ContinueAiWithToolResult(tc.name, result, gen_id);
    });
    connect(cancel_btn, &QPushButton::clicked, card, [this, tc, gen_id, confirm_btn, cancel_btn]() {
        confirm_btn->setEnabled(false);
        cancel_btn->setEnabled(false);
        ContinueAiWithToolResult(tc.name, "Nguoi dung da huy, khong thuc hien hanh dong nay.", gen_id);
    });
}

void MainWindow::ContinueAiWithToolResult(const std::string& tool_name, const std::string& result_text, int gen_id) {
    if (gen_id != ai_gen_id_ || !ai_sending_) return; // aborted meanwhile (Stop clicked)
    ai_add_bubble_(QString::fromUtf8("\xe2\x9c\x93 ") + QString::fromStdString(tool_name + ": " + result_text),
                    Qt::AlignLeft, false);
    ai_history_.push_back({"user", "[TOOL_RESULT " + tool_name + "]\n" + result_text});
    if (ai_history_.size() > 13)
        ai_history_.erase(ai_history_.begin() + 1, ai_history_.begin() + 3);
    RunAiGenerationTurn();
}

} // namespace avdashboard
