#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include "json.hpp"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <fstream>
#include <string>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <chrono>
#include <ctime>
#include <cstdlib>

using json = nlohmann::json;

// ===== Config =====
static const std::string KEYS_DIR = "./"; // p.ej. "/opt/license-keys/"
static const size_t MAX_BODY_SIZE = 1024;
static const int EXPIRY_SECONDS = 3600; // 1 hora
static const int MAX_REQUESTS_PER_MIN = 60; // rate limit simple

// ---- Base64 (sin dependencias) ----
static const char B64_TBL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const unsigned char* data, size_t len) {
    std::string out;
    out.resize(((len + 2) / 3) * 4);
    size_t i = 0, j = 0;
    while (i + 3 <= len) {
        unsigned v = (data[i] << 16) | (data[i+1] << 8) | data[i+2];
        out[j++] = B64_TBL[(v >> 18) & 0x3F];
        out[j++] = B64_TBL[(v >> 12) & 0x3F];
        out[j++] = B64_TBL[(v >> 6)  & 0x3F];
        out[j++] = B64_TBL[(v)       & 0x3F];
        i += 3;
    }
    if (i < len) {
        unsigned v = data[i] << 16;
        if (i + 1 < len) v |= data[i+1] << 8;
        out[j++] = B64_TBL[(v >> 18) & 0x3F];
        out[j++] = B64_TBL[(v >> 12) & 0x3F];
        if (i + 1 < len) {
            out[j++] = B64_TBL[(v >> 6) & 0x3F];
            out[j++] = '=';
        } else {
            out[j++] = '=';
            out[j++] = '=';
        }
    }
    return out;
}

// Lee binario completo a std::string (admite \0)
std::string load_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    return std::string(std::istreambuf_iterator<char>(ifs), {});
}

void set_cors_headers(httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Headers", "*");
    res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
    res.set_header("Vary", "Origin");
}

// Error con CORS y texto plano
void send_error(httplib::Response& res, int status, const std::string& msg) {
    res.status = status;
    set_cors_headers(res);
    res.set_content(msg, "text/plain; charset=utf-8");
}

EVP_PKEY* load_private_key(const std::string& path) {
    FILE* fp = fopen(path.c_str(), "r");
    if (!fp) return nullptr;
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return pkey;
}

std::string sign_payload(const std::string& data, EVP_PKEY* pkey) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    size_t len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    std::string sig(len, '\0');
    if (EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char*>(sig.data()), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        return {};
    }
    sig.resize(len);
    EVP_MD_CTX_free(ctx);
    return base64_encode(reinterpret_cast<const unsigned char*>(sig.data()), sig.size());
}

// Rate limiting simple por IP
std::mutex rl_mutex;
struct RateInfo {
    int count = 0;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
};
std::unordered_map<std::string, RateInfo> rl_map;

bool check_rate_limit(const std::string& ip) {
    std::lock_guard<std::mutex> lock(rl_mutex);
    auto& info = rl_map[ip];
    auto now = std::chrono::steady_clock::now();
    if (now - info.start > std::chrono::minutes(1)) {
        info.start = now;
        info.count = 0;
    }
    if (++info.count > MAX_REQUESTS_PER_MIN) {
        return false;
    }
    return true;
}

int main() {
    const char* cert_file = std::getenv("CERT_FILE");
    const char* key_file = std::getenv("KEY_FILE");
    if (!cert_file) cert_file = "server.crt";
    if (!key_file) key_file = "server.key";

    httplib::SSLServer svr(cert_file, key_file);
    if (!svr.is_valid()) {
        std::cerr << "Failed to start server (check cert/key paths)\n";
        return 1;
    }

    const char* signing_key_path = std::getenv("LICENSE_SIGNING_KEY");
    if (!signing_key_path) signing_key_path = key_file; // reutiliza clave TLS
    EVP_PKEY* signing_key = load_private_key(signing_key_path);
    if (!signing_key) {
        std::cerr << "Missing signing key\n";
        return 1;
    }

    const char* public_key_path = std::getenv("PUBLIC_KEY_FILE");
    if (!public_key_path) public_key_path = cert_file; // enviar certificado

    // Preflight CORS
    svr.Options("/license", [](const httplib::Request&, httplib::Response& res){
        set_cors_headers(res);
        res.status = 204;
    });

    // Endpoint para obtener la clave pública
    svr.Get("/public_key", [public_key_path](const httplib::Request&, httplib::Response& res){
        set_cors_headers(res);
        res.set_header("Cache-Control", "no-store, must-revalidate");
        res.set_header("Pragma", "no-cache");
        res.set_header("Expires", "0");
        const std::string pub = load_file(public_key_path);
        res.set_content(pub, "application/x-pem-file");
    });

    // Licencia
    svr.Post("/license", [signing_key](const httplib::Request& req, httplib::Response& res){
        if (!check_rate_limit(req.remote_addr)) {
            send_error(res, 429, "too many requests");
            return;
        }

        const char* token_env = std::getenv("API_TOKEN");
        std::string expected_token = token_env ? token_env : "demo_token";
        const std::string prefix = "Bearer ";
        auto auth = req.get_header_value("Authorization");
        if (auth.rfind(prefix, 0) != 0 || auth.substr(prefix.size()) != expected_token) {
            send_error(res, 401, "unauthorized");
            return;
        }

        if (req.body.size() > MAX_BODY_SIZE) {
            send_error(res, 413, "payload too large");
            return;
        }

        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            send_error(res, 400, "invalid json");
            return;
        }
        if (!body.contains("content_id") || !body["content_id"].is_string()) {
            send_error(res, 400, "missing content_id");
            return;
        }
        const std::string cid = body["content_id"].get<std::string>();

        const std::string key_path = KEYS_DIR + cid + ".key";
        const std::string key_data = load_file(key_path);
        if (key_data.empty()) {
            send_error(res, 404, "missing key");
            return;
        }

        const std::string b64 = base64_encode(
            reinterpret_cast<const unsigned char*>(key_data.data()),
            key_data.size()
        );

        long expiry = std::time(nullptr) + EXPIRY_SECONDS;
        std::string payload = cid + std::to_string(expiry) + b64;
        std::string sig = sign_payload(payload, signing_key);
        if (sig.empty()) {
            send_error(res, 500, "sign error");
            return;
        }

        json out;
        out["license"] = b64;
        out["expiry"] = expiry;
        out["signature"] = sig;
        set_cors_headers(res);
        res.set_content(out.dump(), "application/json; charset=utf-8");
        res.status = 200;
    });

    std::cout << "License server running on https://0.0.0.0:8443\n";
    svr.listen("0.0.0.0", 8443);
    EVP_PKEY_free(signing_key);
    return 0;
}
