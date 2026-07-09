#include "avai/llm_assistant.hpp"

#include <atomic>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <llama.h>
#include <ggml-backend.h>

namespace avai {

namespace {

constexpr int kMaxGenTokens = 1500;

// Auto-detect a usable GPU. Loads any dynamically-shipped backends (e.g.
// ggml-vulkan.dll) so their devices register, then looks for a GPU device.
// Returns the first GPU device, or nullptr when the machine has none (→ CPU).
ggml_backend_dev_t DetectGpuDevice() {
    ggml_backend_load_all();
    return ggml_backend_dev_by_type(GGML_BACKEND_DEVICE_TYPE_GPU);
}

// Returns the length (in bytes) of the longest valid UTF-8 prefix of s.
// Used to avoid emitting a partial multi-byte sequence mid-stream.
static size_t ValidUtf8Prefix(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        int seqlen;
        if      (c < 0x80)             seqlen = 1;
        else if ((c & 0xE0) == 0xC0)   seqlen = 2;
        else if ((c & 0xF0) == 0xE0)   seqlen = 3;
        else if ((c & 0xF8) == 0xF0)   seqlen = 4;
        else return i; // invalid start byte
        if (i + static_cast<size_t>(seqlen) > s.size()) return i; // incomplete
        for (int j = 1; j < seqlen; ++j)
            if ((static_cast<unsigned char>(s[i+j]) & 0xC0) != 0x80) return i;
        i += static_cast<size_t>(seqlen);
    }
    return i;
}

// Get the embedded chat template from model metadata (or nullptr if none)
const char* GetModelTemplate(llama_model* model) {
    return llama_model_chat_template(model, nullptr);
}

std::string BuildPrompt(llama_model* model, const std::vector<ChatMessage>& history) {
    std::vector<llama_chat_message> msgs;
    msgs.reserve(history.size());
    for (const auto& m : history) {
        msgs.push_back({m.role.c_str(), m.content.c_str()});
    }

    // Use model's embedded template; fall back to ChatML which most instruct models understand
    const char* tmpl = GetModelTemplate(model);
    if (!tmpl || tmpl[0] == '\0') tmpl = "chatml";

    // First call: probe required buffer size
    int needed = llama_chat_apply_template(
        tmpl, msgs.data(), msgs.size(), /*add_ass=*/true, nullptr, 0);

    if (needed <= 0) {
        // Last-resort fallback: hand-build ChatML
        std::string out;
        for (const auto& m : history) {
            out += "<|im_start|>" + m.role + "\n" + m.content + "<|im_end|>\n";
        }
        out += "<|im_start|>assistant\n";
        return out;
    }

    std::vector<char> buf(static_cast<size_t>(needed + 1), '\0');
    llama_chat_apply_template(
        tmpl, msgs.data(), msgs.size(), /*add_ass=*/true,
        buf.data(), static_cast<int>(buf.size()));

    return std::string(buf.data());
}

std::string TokenToPiece(const llama_vocab* vocab, llama_token token) {
    char buf[256] = {};
    const int n = llama_token_to_piece(vocab, token, buf, sizeof(buf) - 1, 0, false);
    if (n < 0) return {};
    return std::string(buf, static_cast<size_t>(n));
}

} // namespace

struct LlmAssistant::Impl {
    llama_model*   model   = nullptr;
    llama_context* ctx     = nullptr;
    std::string    model_path;
    bool           using_gpu = false;
    std::string    backend_name = "CPU";

    std::mutex        gen_mutex;
    std::atomic<bool> abort_flag{false};
    std::atomic<bool> generating{false};

    ~Impl() {
        if (ctx)   llama_free(ctx);
        if (model) llama_model_free(model);
        llama_backend_free();
    }
};

LlmAssistant::LlmAssistant(const std::string& model_path, int n_ctx, int n_threads)
    : impl_(std::make_unique<Impl>()) {
    impl_->model_path = model_path;

    llama_backend_init();

    llama_model_params mparams = llama_model_default_params();
    // Auto GPU/CPU: offload all layers only when a GPU device is actually
    // present on this machine; otherwise run fully on CPU. Works unchanged
    // across machines with or without a discrete/integrated GPU.
    if (ggml_backend_dev_t gpu = DetectGpuDevice()) {
        mparams.n_gpu_layers = 99;
        impl_->using_gpu = true;
        const char* name = ggml_backend_dev_name(gpu);
        impl_->backend_name = (name && name[0]) ? name : "GPU";
    } else {
        mparams.n_gpu_layers = 0;
        impl_->using_gpu = false;
        impl_->backend_name = "CPU";
    }

    impl_->model = llama_model_load_from_file(model_path.c_str(), mparams);
    if (!impl_->model) {
        llama_backend_free();
        throw std::runtime_error("Không thể tải model: " + model_path);
    }

    llama_context_params cparams = llama_context_default_params();
    cparams.n_ctx          = static_cast<uint32_t>(n_ctx);
    cparams.n_threads      = static_cast<uint32_t>(
        n_threads > 0 ? n_threads : static_cast<int>(std::thread::hardware_concurrency()));
    cparams.n_threads_batch = cparams.n_threads;
    // Enable flash attention when any GPU layers are offloaded; llama.cpp
    // falls back silently on backends that don't support it.
    cparams.flash_attn_type = (mparams.n_gpu_layers > 0)
                              ? LLAMA_FLASH_ATTN_TYPE_ENABLED
                              : LLAMA_FLASH_ATTN_TYPE_DISABLED;

    impl_->ctx = llama_init_from_model(impl_->model, cparams);
    if (!impl_->ctx) {
        llama_model_free(impl_->model);
        impl_->model = nullptr;
        llama_backend_free();
        throw std::runtime_error("Không thể tạo context cho model: " + model_path);
    }
}

LlmAssistant::~LlmAssistant() = default;

void LlmAssistant::Abort()              { impl_->abort_flag = true; }
bool LlmAssistant::IsGenerating() const { return impl_->generating.load(); }
std::string LlmAssistant::ModelPath() const { return impl_->model_path; }
bool LlmAssistant::IsUsingGpu() const { return impl_->using_gpu; }
std::string LlmAssistant::BackendName() const { return impl_->backend_name; }

void LlmAssistant::GenerateAsync(std::vector<ChatMessage> history, TokenCallback cb) {
    if (impl_->generating.exchange(true)) return; // already running
    impl_->abort_flag = false;

    std::thread([this, history = std::move(history), cb = std::move(cb)] {
        std::lock_guard<std::mutex> lock(impl_->gen_mutex);

        const llama_vocab* vocab = llama_model_get_vocab(impl_->model);
        const int n_ctx = static_cast<int>(llama_n_ctx(impl_->ctx));

        // Build and tokenize the full prompt
        const std::string prompt = BuildPrompt(impl_->model, history);

        std::vector<llama_token> tokens(static_cast<size_t>(n_ctx));
        const int n_tokens = llama_tokenize(
            vocab,
            prompt.c_str(), static_cast<int>(prompt.size()),
            tokens.data(), n_ctx,
            /*add_special=*/true,
            /*parse_special=*/true);

        if (n_tokens < 0 || n_tokens >= n_ctx) {
            cb("(Lỗi: prompt quá dài cho context window.)", true);
            impl_->generating = false;
            return;
        }
        tokens.resize(static_cast<size_t>(n_tokens));

        // Clear KV cache before prefill
        llama_memory_clear(llama_get_memory(impl_->ctx), /*data=*/false);

        // Prefill (decode the prompt in one batch)
        llama_batch batch = llama_batch_get_one(tokens.data(), n_tokens);
        if (llama_decode(impl_->ctx, batch) != 0) {
            cb("(Lỗi decode prompt.)", true);
            impl_->generating = false;
            return;
        }

        // Build sampler chain: temperature + top-p + greedy tie-break
        llama_sampler_chain_params sparams = llama_sampler_chain_default_params();
        llama_sampler* smpl = llama_sampler_chain_init(sparams);
        llama_sampler_chain_add(smpl, llama_sampler_init_temp(0.7f));
        llama_sampler_chain_add(smpl, llama_sampler_init_top_p(0.9f, 1));
        llama_sampler_chain_add(smpl, llama_sampler_init_greedy());

        // Stop strings that signal end-of-turn for common chat formats
        static const std::vector<std::string> kStopStrings = {
            "<|im_end|>", "<|im_start|>",
            "<|end|>", "<|eot_id|>", "<|endoftext|>", "<|EOT|>",
            "<|user|>", "<|assistant|>",
            "[INST]", "[/INST]", "### Human:", "### User:", "### Assistant:",
            "<s>", "</s>",
        };

        // carry: holds bytes that might form an incomplete UTF-8 sequence or partial stop token
        std::string carry;

        auto flushCarry = [&](bool force) {
            if (carry.empty()) return;
            // Strip any stop strings
            for (const auto& s : kStopStrings) {
                const auto pos = carry.find(s);
                if (pos != std::string::npos) {
                    carry = carry.substr(0, pos);
                    force = true; // emit what's left, then we'll break the loop
                }
            }
            if (carry.empty()) return;
            // Emit only valid UTF-8 prefix; keep remainder in carry
            const size_t safe = ValidUtf8Prefix(carry);
            if (safe > 0) {
                cb(carry.substr(0, safe), false);
                carry = carry.substr(safe);
            }
            if (force && !carry.empty()) {
                // Drop leftover invalid bytes on final flush
                carry.clear();
            }
        };

        bool stop_found = false;

        // Auto-regressive decode loop
        for (int n = 0; n < kMaxGenTokens && !impl_->abort_flag.load() && !stop_found; ++n) {
            const llama_token tok = llama_sampler_sample(smpl, impl_->ctx, -1);
            llama_sampler_accept(smpl, tok);

            if (llama_vocab_is_eog(vocab, tok)) break;

            const std::string piece = TokenToPiece(vocab, tok);
            if (!piece.empty()) {
                carry += piece;

                // Check stop strings in carry
                for (const auto& s : kStopStrings) {
                    if (carry.find(s) != std::string::npos) { stop_found = true; break; }
                }

                // Emit complete UTF-8 chars from the safe prefix
                // Keep a small tail in carry (max stop-string length) for boundary detection
                constexpr size_t kTail = 24;
                if (carry.size() > kTail && !stop_found) {
                    const size_t flush_end = carry.size() - kTail;
                    const std::string to_emit = carry.substr(0, flush_end);
                    const size_t safe = ValidUtf8Prefix(to_emit);
                    if (safe > 0) {
                        cb(carry.substr(0, safe), false);
                        carry = carry.substr(safe);
                    }
                }
            }

            // Feed token back for next step
            llama_token arr[1] = {tok};
            llama_batch next = llama_batch_get_one(arr, 1);
            if (llama_decode(impl_->ctx, next) != 0) break;
        }

        // Final flush of whatever remains in carry
        flushCarry(/*force=*/true);

        llama_sampler_free(smpl);
        cb({}, /*done=*/true);
        impl_->generating = false;
    }).detach();
}

} // namespace avai
