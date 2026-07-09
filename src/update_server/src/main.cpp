#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "avcore/base64.hpp"
#include "avcore/version.hpp"
#include "avstaticscan/hash_signature.hpp"
#include "avstorage/database.hpp"

// AvSuite update server -- local dev stub (Phase 3/5 "cloud backend",
// run locally for now). Serves:
//   * a versioned signature-DB manifest + the signature list itself; see
//     avengine::Engine::CheckForSignatureUpdates for the matching client.
//   * (optional, if --app-binary is given) a signed app-binary update: the
//     manifest additionally carries app_latest_version/app_sha256/
//     app_signature, and /app/download serves the exe. The signature is an
//     Ed25519 signature (over the ASCII hex SHA-256 string) made with
//     --signing-key, verified client-side against a public key baked into
//     the dashboard build (main_window_selfupdate.cpp). This is the actual
//     trust anchor for self-update -- it holds even served over plain HTTP,
//     since a MITM without the private key cannot forge a signature that
//     verifies against the embedded public key.
//
// NOT production-ready as written:
//   - plain HTTP, no TLS -- fine on localhost, not for a real deployment.
//     TLS is still worth adding for confidentiality/availability, but the
//     Ed25519 signature is what actually protects update authenticity here.
//   - /admin/signatures is gated by X-Admin-Key (read from AVSUITE_ADMIN_KEY env
//     var, or a random key printed at startup).
// Deploying this for real: run on an actual host, put TLS in front (e.g. nginx),
// and point avconsolehost.exe --update / the dashboard at that host's URL.

namespace {

std::string BuildSignaturesJson(avstorage::Database& db) {
    nlohmann::json array = nlohmann::json::array();
    for (const auto& record : db.ListAllSignatures()) {
        array.push_back({
            {"sha256", record.sha256},
            {"malware_name", record.malware_name},
            {"severity", static_cast<int>(record.severity)},
        });
    }
    return array.dump();
}

std::string ReadFileBytes(const std::string& path, bool& ok) {
    std::ifstream in(path, std::ios::binary);
    if (!in) { ok = false; return {}; }
    std::ostringstream ss;
    ss << in.rdbuf();
    ok = true;
    return ss.str();
}

// Reads/writes PEM via in-memory BIOs rather than PEM_read_PrivateKey's
// FILE*-based overload, which hits OpenSSL's OPENSSL_Uplink/Applink CRT
// bridging failure when the app wasn't built against applink.c.
EVP_PKEY* LoadPrivateKeyPem(const std::string& path) {
    bool ok = false;
    const std::string pem = ReadFileBytes(path, ok);
    if (!ok) return nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) return nullptr;
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pkey;
}

// One-shot Ed25519 sign (no separate pre-hash -- Ed25519 hashes internally).
std::string SignEd25519(EVP_PKEY* key, const std::string& msg) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    std::string result;
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key) > 0) {
        size_t sig_len = 0;
        const auto* data = reinterpret_cast<const unsigned char*>(msg.data());
        if (EVP_DigestSign(ctx, nullptr, &sig_len, data, msg.size()) > 0) {
            std::vector<unsigned char> sig(sig_len);
            if (EVP_DigestSign(ctx, sig.data(), &sig_len, data, msg.size()) > 0) {
                result = avcore::Base64Encode(sig.data(), sig_len);
            }
        }
    }
    EVP_MD_CTX_free(ctx);
    return result;
}

// Generates a fresh Ed25519 keypair, writes the private key PEM to
// <out_prefix>.pem, and prints the raw public key as hex to embed in the
// client (avdashboard's main_window_selfupdate.cpp kUpdatePublicKey).
// Exits the process -- this is a one-off admin action, not server startup.
[[noreturn]] void RunGenKey(const std::string& out_prefix) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* pkey = nullptr;
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        std::cerr << "Ed25519 keygen failed.\n";
        std::exit(1);
    }
    EVP_PKEY_CTX_free(pctx);

    const std::string pem_path = out_prefix + ".pem";
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem || PEM_write_bio_PrivateKey(mem, pkey, nullptr, nullptr, 0, nullptr, nullptr) <= 0) {
        std::cerr << "Could not serialize private key.\n";
        std::exit(1);
    }
    char* pem_data = nullptr;
    const long pem_len = BIO_get_mem_data(mem, &pem_data);
    std::ofstream out(pem_path, std::ios::binary);
    if (!out || pem_len <= 0) {
        std::cerr << "Could not write private key to " << pem_path << "\n";
        std::exit(1);
    }
    out.write(pem_data, pem_len);
    out.close();
    BIO_free(mem);

    unsigned char pub[32];
    size_t pub_len = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) <= 0) {
        std::cerr << "Could not extract public key.\n";
        std::exit(1);
    }
    EVP_PKEY_free(pkey);

    static const char kHex[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(pub_len * 2);
    for (size_t i = 0; i < pub_len; ++i) {
        hex.push_back(kHex[pub[i] >> 4]);
        hex.push_back(kHex[pub[i] & 0xF]);
    }

    std::cout << "Private key written to " << pem_path << " -- keep this OFF the repo, secret.\n"
              << "Public key (embed as kUpdatePublicKeyHex in main_window_selfupdate.cpp):\n"
              << hex << "\n";
    std::exit(0);
}

bool HexToBytes(const std::string& hex, std::vector<unsigned char>& out) {
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
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

// Standalone sanity check for an (pubkey_hex, message, signature_b64) triple
// -- independent of the dashboard client's own VerifyEd25519 (see
// main_window_selfupdate.cpp), so it can catch a bug in either side rather
// than just confirming they agree with each other. Exits the process.
[[noreturn]] void RunVerify(const std::string& pubkey_hex, const std::string& message,
                             const std::string& sig_b64) {
    std::vector<unsigned char> pubkey_bytes;
    std::vector<unsigned char> sig_bytes;
    if (!HexToBytes(pubkey_hex, pubkey_bytes) || pubkey_bytes.size() != 32) {
        std::cerr << "VERIFY: FAIL (bad public key hex)\n";
        std::exit(1);
    }
    if (!avcore::Base64Decode(sig_b64, sig_bytes)) {
        std::cerr << "VERIFY: FAIL (bad signature base64)\n";
        std::exit(1);
    }
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                  pubkey_bytes.data(), pubkey_bytes.size());
    bool ok = false;
    if (pkey) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) > 0) {
            ok = EVP_DigestVerify(ctx, sig_bytes.data(), sig_bytes.size(),
                                   reinterpret_cast<const unsigned char*>(message.data()),
                                   message.size()) == 1;
        }
        if (ctx) EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
    }
    std::cout << (ok ? "VERIFY: OK\n" : "VERIFY: FAIL\n");
    std::exit(ok ? 0 : 1);
}

} // namespace

int main(int argc, char** argv) {
    std::string db_path = "server_signatures.db";
    int port = 8443;
    std::string app_binary_path;
    std::string app_version = avcore::kAppVersion;
    std::string signing_key_path;
    std::string genkey_prefix;

    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&](const char* flag) -> std::string {
            if (i + 1 >= argc) { std::cerr << flag << " needs a value\n"; std::exit(1); }
            return argv[++i];
        };
        if (arg == "--app-binary") app_binary_path = next("--app-binary");
        else if (arg == "--app-version") app_version = next("--app-version");
        else if (arg == "--signing-key") signing_key_path = next("--signing-key");
        else if (arg == "--genkey") genkey_prefix = next("--genkey");
        else if (arg == "--verify") {
            const std::string pubkey_hex = next("--verify <pubkey_hex>");
            const std::string message = next("--verify <message>");
            const std::string sig_b64 = next("--verify <signature_b64>");
            RunVerify(pubkey_hex, message, sig_b64);
        }
        else positional.push_back(arg);
    }
    if (!genkey_prefix.empty()) RunGenKey(genkey_prefix);
    if (positional.size() > 0) db_path = positional[0];
    if (positional.size() > 1) port = std::atoi(positional[1].c_str());

    // Admin API key read from AVSUITE_ADMIN_KEY env var; generated randomly if absent.
    char* env_buf = nullptr;
    std::size_t env_len = 0;
    _dupenv_s(&env_buf, &env_len, "AVSUITE_ADMIN_KEY");
    const std::unique_ptr<char, decltype(&std::free)> env_guard(env_buf, std::free);
    const char* env_key = env_buf;
    const std::string admin_key = (env_key && *env_key) ? std::string(env_key) : []() {
        // Derive a random-ish default from process start time so it's not a
        // fixed constant, but print it so the operator can use it.
        return "dev-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFF);
    }();

    // App-binary update: load + hash + sign once at startup (not per-request
    // -- the binary and key don't change while the server runs).
    std::string app_binary_bytes;
    std::string app_sha256;
    std::string app_signature_b64;
    bool app_update_configured = false;
    if (!app_binary_path.empty()) {
        bool ok = false;
        app_binary_bytes = ReadFileBytes(app_binary_path, ok);
        if (!ok) {
            std::cerr << "Could not read --app-binary " << app_binary_path << "\n";
            std::exit(1);
        }
        app_sha256 = avstaticscan::ComputeSha256Bytes(app_binary_bytes).value_or("");
        if (signing_key_path.empty()) {
            std::cerr << "--app-binary given without --signing-key -- refusing to serve an "
                         "unsigned app update. Generate a key with --genkey <prefix> first.\n";
            std::exit(1);
        }
        EVP_PKEY* key = LoadPrivateKeyPem(signing_key_path);
        if (!key) {
            std::cerr << "Could not load signing key " << signing_key_path << "\n";
            std::exit(1);
        }
        app_signature_b64 = SignEd25519(key, app_sha256);
        EVP_PKEY_free(key);
        if (app_signature_b64.empty()) {
            std::cerr << "Signing failed.\n";
            std::exit(1);
        }
        app_update_configured = true;
    }

    auto db = avstorage::Database::Open(db_path);
    std::mutex db_mutex;

    httplib::Server server;

    server.Get("/manifest.json", [&](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(db_mutex);
        const std::string payload = BuildSignaturesJson(*db);
        const auto hash = avstaticscan::ComputeSha256Bytes(payload);
        std::string version = db->GetAppliedSignatureDbVersion();
        if (version.empty()) version = "1";

        nlohmann::json manifest = {
            {"db_version", version},
            {"db_sha256", hash.value_or("")},
            {"signature_count", db->ListAllSignatures().size()},
            {"app_latest_version", app_version},
        };
        if (app_update_configured) {
            manifest["app_download_url"] = "/app/download";
            manifest["app_sha256"] = app_sha256;
            manifest["app_signature"] = app_signature_b64;
        }
        res.set_content(manifest.dump(), "application/json");
    });

    server.Get("/signatures.json", [&](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> lock(db_mutex);
        res.set_content(BuildSignaturesJson(*db), "application/json");
    });

    server.Get("/app/download", [&](const httplib::Request&, httplib::Response& res) {
        if (!app_update_configured) {
            res.status = 404;
            return;
        }
        res.set_content(app_binary_bytes, "application/octet-stream");
    });

    server.Post("/admin/signatures", [&](const httplib::Request& req, httplib::Response& res) {
        const auto& key_header = req.get_header_value("X-Admin-Key");
        if (key_header != admin_key) {
            res.status = 401;
            res.set_content(R"({"error":"unauthorized"})", "application/json");
            return;
        }
        std::lock_guard<std::mutex> lock(db_mutex);
        try {
            const auto body = nlohmann::json::parse(req.body);
            avstorage::SignatureRecord record;
            record.sha256 = body.at("sha256").get<std::string>();
            record.malware_name = body.at("malware_name").get<std::string>();
            record.severity = static_cast<avcore::Severity>(body.value("severity", 2));
            db->UpsertSignature(record);

            const std::string current = db->GetAppliedSignatureDbVersion();
            const int next_version = current.empty() ? 2 : std::stoi(current) + 1;
            db->SetAppliedSignatureDbVersion(std::to_string(next_version));

            res.set_content(R"({"status":"ok"})", "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(std::string(R"({"error":")") + e.what() + R"("})", "application/json");
        }
    });

    std::cout << "AvSuite update server listening on http://localhost:" << port << "\n"
              << "Admin key (X-Admin-Key header): " << admin_key << "\n"
              << "Set AVSUITE_ADMIN_KEY env var to use a fixed key.\n";
    if (app_update_configured) {
        std::cout << "App update: version " << app_version << ", sha256 " << app_sha256 << "\n";
    } else {
        std::cout << "App update: not configured (pass --app-binary + --signing-key to enable)\n";
    }
    server.listen("0.0.0.0", port);
    return 0;
}
