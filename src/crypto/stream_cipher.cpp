#include "stream_cipher.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <userver/crypto/hash.hpp>
#include <userver/logging/log.hpp>

#include <iostream>

namespace {

using Encryption = CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption;
using Decryption = CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption;
using StreamFilter = CryptoPP::StreamTransformationFilter;
using ArraySource = CryptoPP::ArraySource;
using ArraySink = CryptoPP::ArraySink;

auto GenerateAesKeyBasedOnPassword(const std::string& password) {
    std::array<uint8_t, CryptoPP::SHA256::DIGESTSIZE> full_hash;
    std::array<uint8_t, CryptoPP::AES::DEFAULT_KEYLENGTH> key;

    CryptoPP::SHA256().CalculateDigest(
        full_hash.data(), reinterpret_cast<const uint8_t*>(password.data()), password.size()
    );

    std::copy(full_hash.begin(), full_hash.begin() + CryptoPP::AES::DEFAULT_KEYLENGTH, key.begin());

    return key;
}

}  // namespace

namespace nuka::crypto {

std::array<uint8_t, StreamCipher::kAesBlockSize> StreamCipher::GenerateAesInitializationVector() {
    std::array<uint8_t, CryptoPP::AES::BLOCKSIZE> iv;
    CryptoPP::AutoSeededRandomPool().GenerateBlock(iv.data(), iv.size());
    return iv;
}

StreamCipher::StreamCipher(const std::string& password) : key_{GenerateAesKeyBasedOnPassword(password)} {}

void StreamCipher::Encrypt(Span<const uint8_t> plaintext, Span<uint8_t> ciphertext) const {
    if (ciphertext.size() < plaintext.size()) {
        throw std::invalid_argument("Ciphertext buffer is too small");
    }

    Encryption encryptor(key_.data(), key_.size(), iv_.data());
    ArraySource(
        plaintext.data(),
        plaintext.size(),
        true,
        new StreamFilter(encryptor, new ArraySink(ciphertext.data(), ciphertext.size()))
    );
}

void StreamCipher::Decrypt(Span<const uint8_t> ciphertext, Span<uint8_t> plaintext) const {
    if (plaintext.size() < ciphertext.size()) {
        throw std::invalid_argument("Plaintext buffer is too small");
    }

    Decryption decryptor(key_.data(), key_.size(), iv_.data());
    ArraySource(
        ciphertext.data(),
        ciphertext.size(),
        true,
        new StreamFilter(decryptor, new ArraySink(plaintext.data(), plaintext.size()))
    );
}

void StreamCipher::SetInitializationVector(Span<const uint8_t> iv) {
    if (iv.size() != kAesBlockSize) {
        throw std::invalid_argument("Invalid IV size");
    }
    std::copy(iv.begin(), iv.end(), iv_.begin());
    iv_set_ = true;
}

}  // namespace nuka::crypto