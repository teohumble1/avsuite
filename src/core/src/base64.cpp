#include "avcore/base64.hpp"

#include <array>

namespace avcore {

namespace {
constexpr char kTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::array<int, 256> BuildDecodeTable() {
    std::array<int, 256> t{};
    t.fill(-1);
    for (int i = 0; i < 64; ++i) t[static_cast<unsigned char>(kTable[i])] = i;
    return t;
}
} // namespace

std::string Base64Encode(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        const std::uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(kTable[(n >> 18) & 0x3F]);
        out.push_back(kTable[(n >> 12) & 0x3F]);
        out.push_back(kTable[(n >> 6) & 0x3F]);
        out.push_back(kTable[n & 0x3F]);
    }
    const std::size_t rem = len - i;
    if (rem == 1) {
        const std::uint32_t n = data[i] << 16;
        out.push_back(kTable[(n >> 18) & 0x3F]);
        out.push_back(kTable[(n >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const std::uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out.push_back(kTable[(n >> 18) & 0x3F]);
        out.push_back(kTable[(n >> 12) & 0x3F]);
        out.push_back(kTable[(n >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

bool Base64Decode(const std::string& in, std::vector<std::uint8_t>& out) {
    static const std::array<int, 256> decode_table = BuildDecodeTable();
    out.clear();
    if (in.empty() || in.size() % 4 != 0) return false;

    std::size_t end = in.size();
    while (end > 0 && in[end - 1] == '=') --end;

    std::uint32_t buffer = 0;
    int bits = 0;
    for (std::size_t i = 0; i < end; ++i) {
        const int v = decode_table[static_cast<unsigned char>(in[i])];
        if (v < 0) return false;
        buffer = (buffer << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return true;
}

} // namespace avcore
