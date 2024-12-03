#pragma once

#include <userver/utils/span.hpp>

#include <array>

namespace nuka::crypto {

class StreamCipher {
public:
    explicit StreamCipher(const std::string& password);

    template <typename T>
    using Span = userver::utils::span<T>;

    static constexpr int kAesKeyLength = 16;
    static constexpr int kAesBlockSize = 16;

    // Шифрование: plaintext -> ciphertext (результат помещается в заранее выделенную область)
    void Encrypt(Span<const uint8_t> plaintext, Span<uint8_t> ciphertext) const;

    // Дешифрование: ciphertext -> plaintext (результат помещается в заранее выделенную область)
    void Decrypt(Span<const uint8_t> ciphertext, Span<uint8_t> plaintext) const;

    void SetInitializationVector(Span<const uint8_t> iv);

    static std::array<uint8_t, kAesBlockSize> GenerateAesInitializationVector();

private:
    const std::array<uint8_t, kAesKeyLength> key_;  // Ключ шифрования
    std::array<uint8_t, kAesBlockSize> iv_;         // Вектор инициализации
    bool iv_set_ = false;
};

}  // namespace nuka::crypto