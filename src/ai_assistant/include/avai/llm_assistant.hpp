#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace avai {

struct ChatMessage {
    std::string role;    // "system" | "user" | "assistant"
    std::string content;
};

// Called once per generated token. When done==true this is the final call
// (content may be empty). Thread: always the inference background thread --
// callers must marshal to the UI thread themselves (e.g. QMetaObject::invokeMethod).
using TokenCallback = std::function<void(const std::string& token_text, bool done)>;

class LlmAssistant {
public:
    // Loads the GGUF model at model_path synchronously. Throws std::runtime_error
    // if the file doesn't exist or fails to load.
    // n_ctx: context window size in tokens (4096 is a safe default for 3B models).
    // n_threads: 0 = auto (uses std::thread::hardware_concurrency).
    explicit LlmAssistant(const std::string& model_path,
                          int n_ctx     = 4096,
                          int n_threads = 0);
    ~LlmAssistant();

    LlmAssistant(const LlmAssistant&) = delete;
    LlmAssistant& operator=(const LlmAssistant&) = delete;

    // Generates a response for `history` asynchronously on an internal thread.
    // The system prompt (if any) must be history[0] with role=="system".
    // `cb` is called with each token as it is generated, and finally with
    // done==true. Only one generation can run at a time; if one is already
    // running, this call returns immediately without starting a new one.
    void GenerateAsync(std::vector<ChatMessage> history, TokenCallback cb);

    // Aborts any in-progress generation after the current token.
    void Abort();

    bool IsGenerating() const;
    std::string ModelPath() const;

    // True if the model was loaded onto a GPU backend. Decided automatically at
    // construction: a real GPU device (Vulkan/CUDA/…) is used when present,
    // otherwise inference runs on CPU. No configuration needed.
    bool IsUsingGpu() const;
    // Human-readable active backend for display, e.g. "Vulkan" or "CPU".
    std::string BackendName() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace avai
