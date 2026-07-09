#pragma once

#include <string>

namespace avpe {

// Verifies the file's Authenticode signature via WinVerifyTrust with
// revocation checking disabled (offline scanner -- no network round-trip).
// Returns false for unsigned files AND for files whose signature doesn't
// verify (expired/tampered/untrusted chain) -- callers only need "trustworthy
// or not", not the failure reason, for this heuristic.
bool IsAuthenticodeSigned(const std::string& path);

} // namespace avpe
