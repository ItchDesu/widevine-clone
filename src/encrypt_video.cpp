#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>

// Helper to generate random key/IV pairs with error checking.
bool generate_key_iv(unsigned char* key, unsigned char* iv, size_t len) {
    if (RAND_bytes(key, len) != 1) return false;
    if (RAND_bytes(iv, len) != 1) return false;
    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <input> <output> <key_file>\n";
        return 1;
    }
    std::ifstream ifs(argv[1], std::ios::binary);
    if (!ifs) { std::cerr << "Cannot open input file\n"; return 1; }
    std::ofstream ofs(argv[2], std::ios::binary);
    std::ofstream kfs(argv[3], std::ios::binary);
    if (!ofs || !kfs) { std::cerr << "Cannot open output/key file\n"; return 1; }

    unsigned char key[16];
    unsigned char iv[16];
    if (!generate_key_iv(key, iv, sizeof(key))) {
        std::cerr << "Random generation failed\n";
        return 1;
    }
    kfs.write(reinterpret_cast<char*>(key), sizeof(key));
    kfs.write(reinterpret_cast<char*>(iv), sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, iv);

    std::vector<unsigned char> in(4096);
    std::vector<unsigned char> out(4096 + EVP_CIPHER_block_size(EVP_aes_128_ctr()));
    int out_len;
    while (ifs.good()) {
        ifs.read(reinterpret_cast<char*>(in.data()), in.size());
        std::streamsize read = ifs.gcount();
        if (read <= 0) break;
        if (EVP_EncryptUpdate(ctx, out.data(), &out_len, in.data(), static_cast<int>(read)) != 1) {
            std::cerr << "Encryption failed\n";
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
        ofs.write(reinterpret_cast<char*>(out.data()), out_len);
    }
    if (EVP_EncryptFinal_ex(ctx, out.data(), &out_len) != 1) {
        std::cerr << "Finalise failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }
    ofs.write(reinterpret_cast<char*>(out.data()), out_len);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
