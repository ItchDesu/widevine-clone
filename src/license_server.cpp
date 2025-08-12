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
        auto cid = req.get_param_value("content_id");
        std::string key_data = load_file(cid + ".key");
        if (key_data.empty()) {
            res.status = 404;
            res.set_content("missing key", "text/plain");
            return;
        }
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Headers", "*");
        res.set_content(key_data, "application/octet-stream");
    });
    std::cout << "License server running on http://localhost:8080\n";
    svr.listen("127.0.0.1", 8080);
    return 0;
}
