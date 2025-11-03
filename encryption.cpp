#include "encryption.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <sstream>
#include <iomanip>

using namespace std;

static string toHex(const unsigned char* data, size_t len) {
    stringstream ss;
    for (size_t i = 0; i < len; ++i)
        ss << hex << setw(2) << setfill('0') << (int)data[i];
    return ss.str();
}

static vector<unsigned char> fromHex(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteStr = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteStr.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

string encrypt(const string& plaintext, const string& keyStr) {
    const int KEY_SIZE = 32; 
    const int IV_SIZE = 16;

    unsigned char key[KEY_SIZE];
    memset(key, 0, KEY_SIZE);
    memcpy(key, keyStr.data(), min(KEY_SIZE, (int)keyStr.size()));

    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len;
    int ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.data(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    string fullHex = toHex(iv, IV_SIZE) + toHex(ciphertext.data(), ciphertext_len);
    return fullHex;
}

string decrypt(const string& cipherHex, const string& keyStr) {
    const int KEY_SIZE = 32;
    const int IV_SIZE = 16;

    vector<unsigned char> fullBytes = fromHex(cipherHex);
    if (fullBytes.size() <= IV_SIZE) return "";

    unsigned char key[KEY_SIZE];
    memset(key, 0, KEY_SIZE);
    memcpy(key, keyStr.data(), min(KEY_SIZE, (int)keyStr.size()));

    unsigned char iv[IV_SIZE];
    memcpy(iv, fullBytes.data(), IV_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    vector<unsigned char> plaintext(fullBytes.size());
    int len;
    int plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, fullBytes.data() + IV_SIZE, fullBytes.size() - IV_SIZE);
    plaintext_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "[decryption failed]";
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return string((char*)plaintext.data(), plaintext_len);
}
