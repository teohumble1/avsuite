// main_window_selfupdate.cpp — Self-Update page.
//
// Checks an avupdateserver instance (src/update_server) for a newer signed
// app build, verifies it (SHA-256 + Ed25519 signature against a public key
// embedded in this binary), and if both check out, swaps the verified
// binary into place and relaunches.
//
// Trust model, spelled out plainly (do not simplify this away later):
//   * The Ed25519 signature is the actual authenticity guarantee -- it is
//     verified against kUpdatePublicKeyHex below, which is baked into THIS
//     binary at build time. The dev update server serves plain HTTP (no
//     TLS), so a network attacker CAN tamper with the manifest/download in
//     transit, but cannot produce a signature that verifies against this
//     key without the matching private key (see update_server's --genkey).
//   * What this does NOT protect against: a compromised signing key/server
//     that legitimately signs a malicious build, or an attacker who has
//     already modified THIS installed binary (the embedded public key goes
//     with it in that case). These are standard self-update caveats, not
//     bugs -- the private key must be guarded like the crown jewels.
//   * The running exe is never overwritten in place: the downloaded build
//     is staged to a temp file and verified FIRST; only then is the
//     current exe renamed aside (<name>.exe.old) and the verified build
//     moved into its place. If any step fails, nothing already on disk is
//     touched (or a best-effort rollback is attempted after the rename).
//   * Server URL is read from Config::update_server_url (Settings JSON) --
//     no UI to edit it yet, matching this page's cut scope; edit the
//     config file directly to point at a non-default server for now.
//
// ASCII labels (MSVC builds without /utf-8).

#include "main_window.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <openssl/evp.h>

#include <atomic>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "avcore/base64.hpp"
#include "avcore/version.hpp"
#include "avstaticscan/hash_signature.hpp"

namespace avdashboard {
namespace {

// Ed25519 public key for this dev deployment's update server, generated via
// `avupdateserver --genkey <prefix>`. Rotating keys means regenerating
// server-side, updating this constant, and rebuilding/redistributing the
// client -- there is deliberately no remote-key-update path (that would
// defeat the point of a fixed trust anchor).
constexpr const char* kUpdatePublicKeyHex =
    "029233fa2760266622c05d33ce5014cb95907c2cf5c30f97e04f520ad1aa8a5e";

bool HexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.empty() || hex.size() % 2 != 0) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.resize(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

bool VerifyEd25519(const std::string& msg, const std::string& sig_b64) {
    std::vector<uint8_t> pubkey_bytes;
    if (!HexToBytes(kUpdatePublicKeyHex, pubkey_bytes) || pubkey_bytes.size() != 32) return false;
    std::vector<uint8_t> sig_bytes;
    if (!avcore::Base64Decode(sig_b64, sig_bytes)) return false;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                  pubkey_bytes.data(), pubkey_bytes.size());
    if (!pkey) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) > 0) {
        ok = EVP_DigestVerify(ctx, sig_bytes.data(), sig_bytes.size(),
                               reinterpret_cast<const uint8_t*>(msg.data()), msg.size()) == 1;
    }
    if (ctx) EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

struct UpdateManifest {
    bool        reachable = false;
    std::string error;
    std::string latest_version;
    std::string download_path; // e.g. "/app/download"
    std::string sha256;
    std::string signature_b64;
    bool        app_update_offered = false; // server has app_download_url/sha256/signature at all
};

UpdateManifest FetchManifest(const std::string& server_url) {
    UpdateManifest m;
    httplib::Client client(server_url);
    client.set_connection_timeout(5);
    auto res = client.Get("/manifest.json");
    if (!res || res->status != 200) {
        m.error = "Could not reach update server at " + server_url;
        return m;
    }
    try {
        const auto j = nlohmann::json::parse(res->body);
        m.latest_version = j.value("app_latest_version", std::string());
        m.download_path  = j.value("app_download_url", std::string());
        m.sha256          = j.value("app_sha256", std::string());
        m.signature_b64   = j.value("app_signature", std::string());
        m.app_update_offered = !m.download_path.empty() && !m.sha256.empty() && !m.signature_b64.empty();
        m.reachable = true;
    } catch (const std::exception&) {
        m.error = "Update server returned an invalid manifest.";
    }
    return m;
}

struct DownloadResult {
    bool         success = false;
    std::string  error;
    std::wstring staged_path;
};

DownloadResult DownloadVerifyAndStage(const std::string& server_url, const UpdateManifest& m) {
    DownloadResult r;
    httplib::Client client(server_url);
    client.set_connection_timeout(10);
    client.set_read_timeout(120);
    auto res = client.Get(m.download_path.c_str());
    if (!res || res->status != 200) {
        r.error = "Download failed.";
        return r;
    }

    const auto actual_hash = avstaticscan::ComputeSha256Bytes(res->body);
    if (!actual_hash || *actual_hash != m.sha256) {
        r.error = "Downloaded build failed the SHA-256 check -- discarded (corrupted or tampered).";
        return r;
    }
    // Signature is verified over the same hex SHA-256 string the manifest
    // carries, matching update_server's SignEd25519(app_sha256) call.
    if (!VerifyEd25519(m.sha256, m.signature_b64)) {
        r.error = "Signature verification failed -- update rejected. The hash matched but the "
                   "Ed25519 signature did not verify against the embedded public key.";
        return r;
    }

    wchar_t temp_dir[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, temp_dir);
    wchar_t temp_file[MAX_PATH] = {};
    if (GetTempFileNameW(temp_dir, L"avu", 0, temp_file) == 0) {
        r.error = "Could not allocate a staging path.";
        return r;
    }
    std::ofstream out(temp_file, std::ios::binary | std::ios::trunc);
    if (!out) {
        r.error = "Could not open staging file for write.";
        return r;
    }
    out.write(res->body.data(), static_cast<std::streamsize>(res->body.size()));
    out.close();
    if (!out) {
        r.error = "Could not write staged build to disk.";
        return r;
    }

    r.success = true;
    r.staged_path = temp_file;
    return r;
}

// Verified-only: caller must have already checked hash + signature. Renames
// the currently-running exe aside rather than overwriting it (Windows
// permits renaming a running exe's file; it does not permit overwriting one
// in place while it's mapped for execution), then moves the staged build
// into the vacated name. Best-effort rollback if the second move fails.
bool ApplyStagedUpdate(const std::wstring& staged_path, std::wstring& out_new_exe_path, std::string& error) {
    wchar_t exe_path[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, exe_path, MAX_PATH) == 0) {
        error = "Could not determine the running exe's path.";
        return false;
    }
    const std::wstring current = exe_path;
    const std::wstring backup = current + L".old";

    DeleteFileW(backup.c_str()); // best-effort cleanup of a stale .old from a prior update
    if (!MoveFileExW(current.c_str(), backup.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        error = "Could not rename the current exe aside.";
        return false;
    }
    if (!MoveFileExW(staged_path.c_str(), current.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        MoveFileExW(backup.c_str(), current.c_str(), MOVEFILE_REPLACE_EXISTING); // rollback
        error = "Could not move the verified build into place -- rolled back.";
        return false;
    }
    out_new_exe_path = current;
    return true;
}

std::atomic<bool> g_quitting{false};

} // namespace

QWidget* BuildSelfUpdatePage(QWidget* parent) {
    auto* page = new QWidget();
    page->setStyleSheet("background:#120B06;");
    auto* root = new QVBoxLayout(page);
    root->setContentsMargins(28, 24, 28, 24);
    root->setSpacing(14);

    auto* title = new QLabel(QString::fromUtf8("Self-Update"), page);
    title->setStyleSheet("color:#ECE4DA; font-size:16pt; font-weight:700; background:transparent;");
    root->addWidget(title);
    auto* sub = new QLabel(QString::fromUtf8(
        "Checks a configured update server for a newer signed app build. Downloads are verified "
        "against a SHA-256 hash AND an Ed25519 signature (embedded public key) before anything on "
        "disk is touched -- a server that can't produce a valid signature cannot push an update, "
        "even over the plain-HTTP dev server."), page);
    sub->setStyleSheet("color:#8B7355; font-size:9pt; background:transparent;");
    sub->setWordWrap(true);
    root->addWidget(sub);

    auto* card = new QFrame(page);
    card->setStyleSheet(
        "QFrame { background:#1A120C; border:1px solid rgba(255,170,90,26); border-radius:10px; }");
    auto* cl = new QVBoxLayout(card);
    cl->setContentsMargins(18, 16, 18, 16);
    cl->setSpacing(10);

    auto* ver_row = new QHBoxLayout();
    auto* current_lbl = new QLabel(
        QString::fromUtf8("Current version: %1").arg(QString::fromLatin1(avcore::kAppVersion)), card);
    current_lbl->setStyleSheet("color:#E8D5C0; font-size:10pt; font-weight:600; background:transparent;");
    ver_row->addWidget(current_lbl);
    ver_row->addStretch();
    cl->addLayout(ver_row);

    auto* status = new QLabel(QString::fromUtf8("Idle."), card);
    status->setStyleSheet("color:#C7B6A2; font-size:9.5pt; background:transparent;");
    status->setWordWrap(true);
    cl->addWidget(status);

    auto* btn_row = new QHBoxLayout();
    btn_row->setSpacing(12);
    auto makeBtn = [card](const QString& text) {
        auto* b = new QPushButton(text, card);
        b->setCursor(Qt::PointingHandCursor);
        b->setStyleSheet(
            "QPushButton { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF7A00,stop:1 #CC5500);"
            " border:none; border-radius:10px; color:#fff; font-size:10.5pt; font-weight:700; padding:10px 22px; }"
            "QPushButton:hover { background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #FF9030,stop:1 #DD6600); }"
            "QPushButton:disabled { background:#3A2A1C; color:#8B7355; }");
        return b;
    };
    auto* check_btn = makeBtn(QString::fromUtf8("Check for update"));
    auto* apply_btn = makeBtn(QString::fromUtf8("Download, verify & install"));
    apply_btn->setEnabled(false);
    btn_row->addWidget(check_btn);
    btn_row->addWidget(apply_btn);
    btn_row->addStretch();
    cl->addLayout(btn_row);

    root->addWidget(card);
    root->addStretch();

    auto busy = std::make_shared<std::atomic<bool>>(false);
    auto last_manifest = std::make_shared<UpdateManifest>();
    const QString server_url = qobject_cast<MainWindow*>(parent)
                                    ? qobject_cast<MainWindow*>(parent)->UpdateServerUrl()
                                    : QString::fromLatin1("http://localhost:8443");

    QObject::connect(qApp, &QCoreApplication::aboutToQuit, page, [] { g_quitting.store(true); });

    QObject::connect(check_btn, &QPushButton::clicked, page,
        [page, check_btn, apply_btn, status, busy, last_manifest, server_url] {
        if (busy->load()) return;
        busy->store(true);
        check_btn->setEnabled(false);
        apply_btn->setEnabled(false);
        status->setText(QString::fromUtf8("Checking %1 ...").arg(server_url));
        const std::string url = server_url.toStdString();
        std::thread([status, check_btn, apply_btn, busy, last_manifest, url] {
            auto m = FetchManifest(url);
            if (g_quitting.load()) { busy->store(false); return; }
            *last_manifest = m;

            QString text;
            bool offer_apply = false;
            if (!m.reachable) {
                text = QString::fromUtf8("Error: %1").arg(QString::fromStdString(m.error));
            } else if (!m.app_update_offered) {
                text = QString::fromUtf8("Server reached, but no app update is configured there.");
            } else if (m.latest_version == avcore::kAppVersion) {
                text = QString::fromUtf8("Up to date (version %1).").arg(QString::fromLatin1(avcore::kAppVersion));
            } else {
                text = QString::fromUtf8("Update available: %1 -> %2")
                           .arg(QString::fromLatin1(avcore::kAppVersion), QString::fromStdString(m.latest_version));
                offer_apply = true;
            }

            QMetaObject::invokeMethod(status, [status, text] { status->setText(text); }, Qt::QueuedConnection);
            QMetaObject::invokeMethod(check_btn, [check_btn] { check_btn->setEnabled(true); }, Qt::QueuedConnection);
            if (offer_apply) {
                QMetaObject::invokeMethod(apply_btn, [apply_btn] { apply_btn->setEnabled(true); }, Qt::QueuedConnection);
            }
            busy->store(false);
        }).detach();
    });

    QObject::connect(apply_btn, &QPushButton::clicked, page,
        [page, check_btn, apply_btn, status, busy, last_manifest, server_url] {
        if (busy->load()) return;
        const auto reply = QMessageBox::question(page, QString::fromUtf8("Confirm update"),
            QString::fromUtf8("Download, verify, and install version %1? The app will restart.")
                .arg(QString::fromStdString(last_manifest->latest_version)),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (reply != QMessageBox::Yes) return;

        busy->store(true);
        check_btn->setEnabled(false);
        apply_btn->setEnabled(false);
        status->setText(QString::fromUtf8("Downloading..."));
        const std::string url = server_url.toStdString();
        const UpdateManifest manifest = *last_manifest;
        std::thread([page, status, check_btn, busy, url, manifest] {
            const auto dl = DownloadVerifyAndStage(url, manifest);
            if (g_quitting.load()) { busy->store(false); return; }
            if (!dl.success) {
                const QString err = QString::fromStdString(dl.error);
                QMetaObject::invokeMethod(status, [status, err] {
                    status->setText(QString::fromUtf8("Failed: %1").arg(err));
                }, Qt::QueuedConnection);
                QMetaObject::invokeMethod(check_btn, [check_btn] { check_btn->setEnabled(true); }, Qt::QueuedConnection);
                busy->store(false);
                return;
            }

            std::wstring new_exe;
            std::string apply_error;
            if (!ApplyStagedUpdate(dl.staged_path, new_exe, apply_error)) {
                const QString err = QString::fromStdString(apply_error);
                QMetaObject::invokeMethod(status, [status, err] {
                    status->setText(QString::fromUtf8("Failed: %1").arg(err));
                }, Qt::QueuedConnection);
                QMetaObject::invokeMethod(check_btn, [check_btn] { check_btn->setEnabled(true); }, Qt::QueuedConnection);
                busy->store(false);
                return;
            }

            if (g_quitting.load()) { busy->store(false); return; }
            QMetaObject::invokeMethod(page, [new_exe] {
                QProcess::startDetached(QString::fromStdWString(new_exe), {});
                QApplication::quit();
            }, Qt::QueuedConnection);
            busy->store(false);
        }).detach();
    });

    return page;
}

} // namespace avdashboard
