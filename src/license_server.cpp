#include "httplib.h"
#include <fstream>
#include <string>
#include <iostream>

std::string load_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    return std::string((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
}

int main() {
    httplib::Server svr;
    svr.Options("/license", [](const httplib::Request&, httplib::Response& res){
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "*");
        res.status = 204;
    });

    svr.Post("/license", [](const httplib::Request& req, httplib::Response& res){
        auto body = req.body;
        auto pos = body.find("\"content_id\"");
        if (pos == std::string::npos) {
            res.status = 400;
            res.set_content("missing content_id", "text/plain");
            return;
        }
        pos = body.find(':', pos);
        pos = body.find('"', pos);
        auto end = body.find('"', pos + 1);
        std::string cid = body.substr(pos + 1, end - pos - 1);

        std::string key_data = load_file(cid + ".key");
        if (key_data.empty()) {
            res.status = 404;
            res.set_content("missing key", "text/plain");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Headers", "*");
        std::string b64 = httplib::detail::base64_encode(key_data);
        res.set_content("{\"license\":\"" + b64 + "\"}", "application/json");
    });
    std::cout << "License server running on http://localhost:8080\n";
    svr.listen("127.0.0.1", 8080);
    return 0;
}
