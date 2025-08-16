// server.cpp
#include "httplib.h"
#include <fstream>
#include <string>
#include <iostream>
#include <optional>
#include <regex>

// ===== Config =====
static const std::string KEYS_DIR = "./"; // p.ej. "/opt/license-keys/"

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
    res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set_header("Vary", "Origin");
}

// Error con CORS y texto plano
void send_error(httplib::Response& res, int status, const std::string& msg) {
    res.status = status;
    set_cors_headers(res);
    res.set_content(msg, "text/plain; charset=utf-8");
}

// Extrae content_id de JSON simple: {"content_id":"..."}.
// Permite A-Za-z0-9 _ -  (si quieres puntos, añade '.' en la clase).
std::optional<std::string> extract_content_id(const std::string& body) {
    static const std::regex re(
        R"CID("content_id"\s*:\s*"([A-Za-z0-9_-]+)")CID",
        std::regex::ECMAScript
    );
    std::smatch m;
    if (!std::regex_search(body, m, re)) return std::nullopt;
    return m[1].str();
}

int main() {
    httplib::Server svr;

    // Preflight CORS
    svr.Options("/license", [](const httplib::Request&, httplib::Response& res){
        set_cors_headers(res);
        res.status = 204;
    });

    // Licencia
    svr.Post("/license", [](const httplib::Request& req, httplib::Response& res){
        // Limitar tamaño del body (defensa básica)
        if (req.body.size() > 1024) {
            send_error(res, 413, "payload too large");
            return;
        }

        // Extraer y validar content_id
        auto cid_opt = extract_content_id(req.body);
        if (!cid_opt) {
            send_error(res, 400, "invalid content_id");
            return;
        }
        const std::string cid = *cid_opt;

        // Construir ruta y cargar .key (binario)
        const std::string key_path = KEYS_DIR + cid + ".key";
        const std::string key_data = load_file(key_path);
        if (key_data.empty()) {
            send_error(res, 404, "missing key");
            return;
        }

        // Responder JSON con base64
        set_cors_headers(res);
        const std::string b64 = base64_encode(
            reinterpret_cast<const unsigned char*>(key_data.data()),
            key_data.size()
        );
        std::string json = std::string("{\"license\":\"") + b64 + "\"}";
        res.set_content(json, "application/json; charset=utf-8");
        res.status = 200;
    });

    std::cout << "License server running on http://0.0.0.0:8080\n";
    svr.listen("0.0.0.0", 8080);
    return 0;
}