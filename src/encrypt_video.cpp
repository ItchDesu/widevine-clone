#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>

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
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
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
        EVP_EncryptUpdate(ctx, out.data(), &out_len, in.data(), read);
        ofs.write(reinterpret_cast<char*>(out.data()), out_len);
    }
    EVP_EncryptFinal_ex(ctx, out.data(), &out_len);
    ofs.write(reinterpret_cast<char*>(out.data()), out_len);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
