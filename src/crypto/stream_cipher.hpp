#pragma once

#include <cryptopp/aes.h>
#include <userver/utils/span.hpp>

#include <array>

namespace nuka::crypto {

class StreamCipher {
public:
    explicit StreamCipher(const std::string& password);

    template <typename T>
    using Span = userver::utils::span<T>;

    static constexpr int kAesKeyLength = CryptoPP::AES::DEFAULT_KEYLENGTH;
    static constexpr int kAesBlockSize = CryptoPP::AES::BLOCKSIZE;

    // Шифрование: plaintext -> ciphertext (результат помещается в заранее выделенную область)
    void Encrypt(Span<const uint8_t> plaintext, Span<const uint8_t> iv, Span<uint8_t> ciphertext) const;

    // Дешифрование: ciphertext -> plaintext (результат помещается в заранее выделенную область)
    void Decrypt(Span<const uint8_t> ciphertext, Span<const uint8_t> iv, Span<uint8_t> plaintext) const;

private:
    const std::array<uint8_t, kAesKeyLength> key_;  // Ключ шифрования
};

}  // namespace nuka::crypto