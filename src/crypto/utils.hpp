#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/seckey.h>

#include <array>
#include <string>

namespace nuka::crypto {

template <size_t KeyLength = CryptoPP::AES::DEFAULT_KEYLENGTH>
std::array<uint8_t, KeyLength> GenerateAesKey(const std::string& password) {
    std::array<uint8_t, KeyLength> key;
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(reinterpret_cast<const uint8_t*>(password.data()), password.size());
    hmac.CalculateTruncatedDigest(key.data(), key.size(), nullptr, 0);
    return key;
}

template <size_t BlockSize = CryptoPP::AES::BLOCKSIZE>
std::array<uint8_t, BlockSize> GenerateRandomIV() {
    std::array<uint8_t, BlockSize> iv;
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(iv.data(), iv.size());
    return iv;
}

}  // namespace nuka::crypto
