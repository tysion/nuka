#include "stream_cipher.hpp"
#include "utils.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <userver/utest/utest.hpp>
#include <userver/utils/span.hpp>

#include <vector>

using namespace nuka::crypto;

// Фиксированный пароль для тестов
constexpr const char* kTestPassword = "test_password";

// Тестовый набор для StreamCipher
class StreamCipherTest : public ::testing::Test {
protected:
    void SetUp() override {
        cipher_ = std::make_unique<StreamCipher>(kTestPassword);
        iv_ = GenerateRandomIV();
    }

    std::unique_ptr<StreamCipher> cipher_;
    std::array<uint8_t, StreamCipher::kAesBlockSize> iv_;
};

// Тест шифрования и дешифрования короткого сообщения
TEST_F(StreamCipherTest, EncryptDecrypt_ShortMessage) {
    std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> decrypted(plaintext.size());

    cipher_->Encrypt(plaintext, iv_, ciphertext);
    cipher_->Decrypt(ciphertext, iv_, decrypted);

    EXPECT_EQ(plaintext, decrypted) << "Decrypted text does not match original plaintext.";
}

// Тест шифрования и дешифрования сообщения длиной в несколько блоков
TEST_F(StreamCipherTest, EncryptDecrypt_MultiBlockMessage) {
    std::vector<uint8_t> plaintext(48, 'A');  // Сообщение длиной 3 блока AES
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> decrypted(plaintext.size());

    cipher_->Encrypt(plaintext, iv_, ciphertext);
    cipher_->Decrypt(ciphertext, iv_, decrypted);

    EXPECT_EQ(plaintext, decrypted) << "Decrypted text does not match original plaintext.";
}

// Тест корректности обработки пустого сообщения
TEST_F(StreamCipherTest, EncryptDecrypt_EmptyMessage) {
    std::vector<uint8_t> plaintext;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> decrypted;

    cipher_->Encrypt(plaintext, iv_, ciphertext);
    cipher_->Decrypt(ciphertext, iv_, decrypted);

    EXPECT_EQ(plaintext, decrypted) << "Empty message should result in empty output.";
}

// Тест обработки данных, не кратных размеру блока
TEST_F(StreamCipherTest, EncryptDecrypt_NonBlockAlignedMessage) {
    std::vector<uint8_t> plaintext(23, 'B');  // Сообщение не кратно 16 байтам (размеру блока AES)
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> decrypted(plaintext.size());

    cipher_->Encrypt(plaintext, iv_, ciphertext);
    cipher_->Decrypt(ciphertext, iv_, decrypted);

    EXPECT_EQ(
        plaintext, decrypted
    ) << "Decrypted text does not match original plaintext for non-block-aligned message.";
}

// Тест повторного использования объекта для нескольких операций
TEST_F(StreamCipherTest, EncryptDecrypt_MultipleOperations) {
    std::vector<uint8_t> plaintext1 = {'F', 'i', 'r', 's', 't'};
    std::vector<uint8_t> plaintext2 = {'S', 'e', 'c', 'o', 'n', 'd'};

    std::vector<uint8_t> ciphertext1(plaintext1.size());
    std::vector<uint8_t> ciphertext2(plaintext2.size());

    std::vector<uint8_t> decrypted1(plaintext1.size());
    std::vector<uint8_t> decrypted2(plaintext2.size());

    // Первая операция
    cipher_->Encrypt(plaintext1, iv_, ciphertext1);
    cipher_->Decrypt(ciphertext1, iv_, decrypted1);

    EXPECT_EQ(plaintext1, decrypted1) << "First operation failed.";

    // Вторая операция
    cipher_->Encrypt(plaintext2, iv_, ciphertext2);
    cipher_->Decrypt(ciphertext2, iv_, decrypted2);

    EXPECT_EQ(plaintext2, decrypted2) << "Second operation failed.";
}

TEST_F(StreamCipherTest, StreamEncryptionDecryption) {
    // Большой текст (например, 10 * 64 байт)
    std::string original_text(640, 'A');
    std::vector<uint8_t> plaintext(original_text.begin(), original_text.end());

    // Буфер для зашифрованного текста
    std::vector<uint8_t> encrypted_text(plaintext.size() + StreamCipher::kAesBlockSize);

    // Буфер для расшифрованного текста
    std::vector<uint8_t> decrypted_text(plaintext.size());

    // Генерация IV
    std::array<uint8_t, StreamCipher::kAesBlockSize> iv = GenerateRandomIV();

    // Шифрование
    const auto cipher_encrypt = StreamCipher(kTestPassword);
    auto iv_encrypt = userver::utils::span(iv.data(), iv.size());
    std::copy(iv_encrypt.begin(), iv_encrypt.end(), encrypted_text.begin());  // Первый блок для IV
    for (size_t offset = 0; offset < plaintext.size(); offset += StreamCipher::kAesBlockSize) {
        auto chunk = userver::utils::span(
            plaintext.data() + offset, std::min<size_t>(StreamCipher::kAesBlockSize, plaintext.size() - offset)
        );
        auto encrypted_chunk =
            userver::utils::span(encrypted_text.data() + offset + StreamCipher::kAesBlockSize, chunk.size());
        cipher_encrypt.Encrypt(chunk, iv_encrypt, encrypted_chunk);
        iv_encrypt = encrypted_chunk;
    }

    // Дешифрование
    const auto cipher_decrypt = StreamCipher(kTestPassword);
    auto iv_decrypt = userver::utils::span(encrypted_text.data(), StreamCipher::kAesBlockSize);  // Установка IV
    for (size_t offset = 0; offset < decrypted_text.size(); offset += StreamCipher::kAesBlockSize) {
        auto encrypted_chunk = userver::utils::span(
            encrypted_text.data() + offset + StreamCipher::kAesBlockSize,
            std::min<size_t>(StreamCipher::kAesBlockSize, decrypted_text.size() - offset)
        );
        auto decrypted_chunk = userver::utils::span(decrypted_text.data() + offset, encrypted_chunk.size());
        cipher_decrypt.Decrypt(encrypted_chunk, iv_decrypt, decrypted_chunk);
        iv_decrypt = encrypted_chunk;
    }

    // Проверка, что исходный текст и расшифрованный совпадают
    EXPECT_EQ(plaintext, decrypted_text) << "Decrypted text does not match original text.";
}
