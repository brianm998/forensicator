#include "forensicator/sha512.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <vector>

#if defined(FORENSICATOR_USE_OPENSSL)
#  include <openssl/evp.h>
#endif

namespace forensicator {

#if defined(FORENSICATOR_USE_OPENSSL)

struct Sha512Impl {
    EVP_MD_CTX* ctx = nullptr;
};

Sha512::Sha512() {
    auto* impl = new Sha512Impl;
    impl->ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(impl->ctx, EVP_sha512(), nullptr);
    impl_ = impl;
}

Sha512::~Sha512() {
    if (impl_) {
        auto* impl = static_cast<Sha512Impl*>(impl_);
        if (impl->ctx) EVP_MD_CTX_free(impl->ctx);
        delete impl;
    }
}

Sha512::Sha512(Sha512&& o) noexcept : impl_(o.impl_) { o.impl_ = nullptr; }
Sha512& Sha512::operator=(Sha512&& o) noexcept {
    if (this != &o) {
        if (impl_) {
            auto* impl = static_cast<Sha512Impl*>(impl_);
            if (impl->ctx) EVP_MD_CTX_free(impl->ctx);
            delete impl;
        }
        impl_ = o.impl_;
        o.impl_ = nullptr;
    }
    return *this;
}

void Sha512::update(const void* data, std::size_t len) {
    auto* impl = static_cast<Sha512Impl*>(impl_);
    EVP_DigestUpdate(impl->ctx, data, len);
}

std::string Sha512::hex_digest() {
    auto* impl = static_cast<Sha512Impl*>(impl_);
    unsigned char out[64];
    unsigned int outlen = 0;
    EVP_DigestFinal_ex(impl->ctx, out, &outlen);
    static const char* hex = "0123456789abcdef";
    std::string r;
    r.resize(outlen * 2);
    for (unsigned i = 0; i < outlen; ++i) {
        r[2 * i]     = hex[(out[i] >> 4) & 0xF];
        r[2 * i + 1] = hex[out[i] & 0xF];
    }
    return r;
}

#else  // ---- Vendored SHA-512 implementation ----

namespace sha512_vendored {

struct Ctx {
    std::uint64_t state[8];
    std::uint64_t bitlen_hi;
    std::uint64_t bitlen_lo;
    unsigned char buf[128];
    std::size_t  buflen;
};

static const std::uint64_t K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL,
};

static inline std::uint64_t rotr(std::uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}

static void init(Ctx* c) {
    c->state[0] = 0x6a09e667f3bcc908ULL;
    c->state[1] = 0xbb67ae8584caa73bULL;
    c->state[2] = 0x3c6ef372fe94f82bULL;
    c->state[3] = 0xa54ff53a5f1d36f1ULL;
    c->state[4] = 0x510e527fade682d1ULL;
    c->state[5] = 0x9b05688c2b3e6c1fULL;
    c->state[6] = 0x1f83d9abfb41bd6bULL;
    c->state[7] = 0x5be0cd19137e2179ULL;
    c->bitlen_hi = 0;
    c->bitlen_lo = 0;
    c->buflen = 0;
}

static void transform(Ctx* c, const unsigned char block[128]) {
    std::uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint64_t>(block[i * 8])     << 56) |
               (static_cast<std::uint64_t>(block[i * 8 + 1]) << 48) |
               (static_cast<std::uint64_t>(block[i * 8 + 2]) << 40) |
               (static_cast<std::uint64_t>(block[i * 8 + 3]) << 32) |
               (static_cast<std::uint64_t>(block[i * 8 + 4]) << 24) |
               (static_cast<std::uint64_t>(block[i * 8 + 5]) << 16) |
               (static_cast<std::uint64_t>(block[i * 8 + 6]) <<  8) |
               (static_cast<std::uint64_t>(block[i * 8 + 7]));
    }
    for (int i = 16; i < 80; ++i) {
        std::uint64_t s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
        std::uint64_t s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint64_t a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
    std::uint64_t e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];
    for (int i = 0; i < 80; ++i) {
        std::uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        std::uint64_t ch = (e & f) ^ (~e & g);
        std::uint64_t t1 = h + S1 + ch + K[i] + w[i];
        std::uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        std::uint64_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        std::uint64_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void update(Ctx* c, const unsigned char* data, std::size_t len) {
    // Update bit length (128-bit total).
    std::uint64_t add = static_cast<std::uint64_t>(len) << 3;
    std::uint64_t carry = (len >> 61);  // overflow of the shift
    std::uint64_t old_lo = c->bitlen_lo;
    c->bitlen_lo += add;
    if (c->bitlen_lo < old_lo) ++c->bitlen_hi;
    c->bitlen_hi += carry;

    if (c->buflen) {
        std::size_t need = 128 - c->buflen;
        if (len < need) {
            std::memcpy(c->buf + c->buflen, data, len);
            c->buflen += len;
            return;
        }
        std::memcpy(c->buf + c->buflen, data, need);
        transform(c, c->buf);
        data += need; len -= need; c->buflen = 0;
    }
    while (len >= 128) {
        transform(c, data);
        data += 128; len -= 128;
    }
    if (len) {
        std::memcpy(c->buf, data, len);
        c->buflen = len;
    }
}

static void final(Ctx* c, unsigned char out[64]) {
    std::uint64_t hi = c->bitlen_hi;
    std::uint64_t lo = c->bitlen_lo;

    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 112) {
        std::memset(c->buf + c->buflen, 0, 128 - c->buflen);
        transform(c, c->buf);
        c->buflen = 0;
    }
    std::memset(c->buf + c->buflen, 0, 112 - c->buflen);
    for (int i = 0; i < 8; ++i) {
        c->buf[112 + i] = static_cast<unsigned char>((hi >> (56 - i * 8)) & 0xFF);
        c->buf[120 + i] = static_cast<unsigned char>((lo >> (56 - i * 8)) & 0xFF);
    }
    transform(c, c->buf);
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            out[i * 8 + j] = static_cast<unsigned char>((c->state[i] >> (56 - j * 8)) & 0xFF);
        }
    }
}

}  // namespace sha512_vendored

struct Sha512Impl {
    sha512_vendored::Ctx ctx{};
};

Sha512::Sha512() {
    auto* impl = new Sha512Impl;
    sha512_vendored::init(&impl->ctx);
    impl_ = impl;
}

Sha512::~Sha512() {
    delete static_cast<Sha512Impl*>(impl_);
}

Sha512::Sha512(Sha512&& o) noexcept : impl_(o.impl_) { o.impl_ = nullptr; }
Sha512& Sha512::operator=(Sha512&& o) noexcept {
    if (this != &o) {
        delete static_cast<Sha512Impl*>(impl_);
        impl_ = o.impl_;
        o.impl_ = nullptr;
    }
    return *this;
}

void Sha512::update(const void* data, std::size_t len) {
    auto* impl = static_cast<Sha512Impl*>(impl_);
    sha512_vendored::update(&impl->ctx,
                            static_cast<const unsigned char*>(data), len);
}

std::string Sha512::hex_digest() {
    auto* impl = static_cast<Sha512Impl*>(impl_);
    unsigned char out[64];
    sha512_vendored::final(&impl->ctx, out);
    static const char* hex = "0123456789abcdef";
    std::string r;
    r.resize(128);
    for (int i = 0; i < 64; ++i) {
        r[2 * i]     = hex[(out[i] >> 4) & 0xF];
        r[2 * i + 1] = hex[out[i] & 0xF];
    }
    return r;
}

#endif

std::optional<std::string> sha512_file(const std::filesystem::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    if (!ifs) return std::nullopt;
    Sha512 h;
    std::vector<char> buf(1 << 20);  // 1 MiB
    while (ifs) {
        ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        std::streamsize got = ifs.gcount();
        if (got > 0) h.update(buf.data(), static_cast<std::size_t>(got));
        if (ifs.bad()) return std::nullopt;
    }
    return h.hex_digest();
}

}  // namespace forensicator
