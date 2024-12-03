#include "stream_cipher.hpp"
#include "utils.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
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

}  // namespace

namespace nuka::crypto {

StreamCipher::StreamCipher(const std::string& password) : key_{GenerateAesKey(password)} {}

void StreamCipher::Encrypt(Span<const uint8_t> plaintext, Span<const uint8_t> iv, Span<uint8_t> ciphertext) const {
    if (iv.size() != kAesBlockSize) {
        throw std::invalid_argument("IV size is invalid");
    }

    if (ciphertext.size() < plaintext.size()) {
        throw std::invalid_argument("Ciphertext buffer is too small");
    }

    Encryption encryptor(key_.data(), key_.size(), iv.data());
    ArraySource(
        plaintext.data(),
        plaintext.size(),
        true,
        new StreamFilter(encryptor, new ArraySink(ciphertext.data(), ciphertext.size()))
    );
}

void StreamCipher::Decrypt(Span<const uint8_t> ciphertext, Span<const uint8_t> iv, Span<uint8_t> plaintext) const {
    if (iv.size() != kAesBlockSize) {
        throw std::invalid_argument("IV size is invalid");
    }

    if (plaintext.size() < ciphertext.size()) {
        throw std::invalid_argument("Plaintext buffer is too small");
    }

    Decryption decryptor(key_.data(), key_.size(), iv.data());
    ArraySource(
        ciphertext.data(),
        ciphertext.size(),
        true,
        new StreamFilter(decryptor, new ArraySink(plaintext.data(), plaintext.size()))
    );
}

}  // namespace nuka::crypto